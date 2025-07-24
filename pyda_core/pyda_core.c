#include "pyda_core.h"
#include "pyda_threads.h"
#include "pyda_util.h"
#include <fcntl.h>

#if defined(LINUX)
#include <pty.h>
#include <sys/syscall.h>
#elif defined(MACOS)
#include <util.h>
/* TODO: fix test_io for macos, it probably doesn't work... */
#define SYS_read 0
#define SYS_write 1
#endif

#define CONTEXT_STACK_LIMIT 10

#ifndef PYDA_DYNAMORIO_CLIENT

pyda_process* pyda_mk_process() {
    // TODO: We might be able to use this to fork and launch the process
    // (in which the entire python file will be reparsed...)
    ABORT_IF_NODYNAMORIO;
}

#else
#include "dr_api.h"

static void free_hook_step1(void *data) {
    // Must hold GIL
    pyda_hook *hook = (pyda_hook*)data;
    Py_DECREF(hook->py_func);
    hook->py_func = NULL;
}

static void free_hook_step2(void *data) {
    // no GIL required
    dr_global_free(data, sizeof(pyda_hook));
}

static void thread_prepare_for_python_entry(PyGILState_STATE *gstate, pyda_thread *t, void* pc);
static void thread_prepare_for_python_return(pyda_thread *t, void* hook_addr);


pyda_process* pyda_mk_process() {
    ABORT_IF_NODYNAMORIO;

    pyda_process *proc = dr_global_alloc(sizeof(pyda_process));
    proc->refcount = 0; // xxx: will be incremented to 1 by first pyda_mk_thread
    proc->flush_count = 0;
    drvector_init(&proc->threads, 0, true, NULL);
    drvector_init(&proc->thread_run_untils, 0, true, NULL);

    proc->main_thread = pyda_mk_thread(proc);
    hashtable_init_ex(&proc->callbacks, 4, HASH_INTPTR, false, false, NULL, NULL, NULL);

    proc->thread_init_hook = NULL;
    proc->syscall_pre_hook = NULL;
    proc->syscall_post_hook = NULL;
    proc->module_load_hook = NULL;
    proc->py_obj = NULL;

    // Setup locks, etc.
    pthread_condattr_t condattr;
    int ret;
    pthread_condattr_init(&condattr);

#ifdef LINUX
    if ((ret = pthread_condattr_setpshared(&condattr, PTHREAD_PROCESS_SHARED))) {
        dr_fprintf(STDERR, "pthread_condattr_setpshared failed: %d\n", ret);
        dr_abort();
    }
#endif // LINUX
    if ((ret = pthread_cond_init(&proc->thread_exit_cond, &condattr))) {
        dr_fprintf(STDERR, "pthread_cond_init failed %d\n", ret);
        dr_abort();
    }

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL);

#ifdef LINUX
    if ((ret = pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED))) {
        dr_fprintf(STDERR, "pthread_mutexattr_setpshared failed %d\n", ret);
        dr_abort();
    }
#endif

    if ((ret = pthread_mutex_init(&proc->refcount_mutex, &attr))) {
        dr_fprintf(STDERR, "pthread_mutex_init failed %d\n", ret);
        dr_abort();
    }

    // Setup I/O
    proc->stdin_fd = -1;
    proc->stdout_fd = -1;
    proc->stderr_fd = -1;

    // TODO: also need to modify dynamorio printing functions
    // as they use raw fd 0/1/2
    return proc;
}

extern file_t our_stderr;

void pyda_capture_io(pyda_process *proc, int use_pty, int pty_raw) {
    if (use_pty) {
        int master, slave;

        if (openpty(&master, &slave, NULL, NULL, NULL)) {
            // Failed to open TTY
            DEBUG_PRINTF("Failed to open TTY err %s\n", strerror(errno));
            use_pty = false;
        } else {
            dup2(slave, 0);
            dup2(slave, 1);
            dup2(slave, 2);
            proc->stdin_fd = dup(master);
            proc->stdout_fd = dup(master);
            proc->stderr_fd = dup(master);

            // Modify tty attributes
            struct termios tmios;
            if (tcgetattr(master, &tmios)) {
                DEBUG_PRINTF("Failed to get termios\n");
            } else {
                if (pty_raw)
                    cfmakeraw(&tmios);

                // Always: no echo
                tmios.c_lflag &= ~(ECHO);

                if (tcsetattr(master, TCSANOW, &tmios)) {
                    DEBUG_PRINTF("Failed to set termios\n");
                }
            }
        }
    }

    if (!use_pty) { // We were asked not to use a pty, or pty init failed
        int pipe1[2], pipe2[2], pipe3[2];
        if (pipe(pipe1) || pipe(pipe2) || pipe(pipe3)) {
            dr_fprintf(STDERR, "Failed to create pipes\n");
            dr_abort();
        }

        // Try to make a larger pipe (1M)
#ifdef LINUX
        if (fcntl(pipe1[0], F_SETPIPE_SZ, 1024*1024) || fcntl(pipe2[0], F_SETPIPE_SZ, 1024*1024) || fcntl(pipe3[0], F_SETPIPE_SZ, 1024*1024)) {
            DEBUG_PRINTF("Failed to set pipe size to 1M\n");
        }
#endif

        dup2(pipe1[0], 0);
        dup2(pipe2[1], 1);
        dup2(pipe3[1], 2);

        proc->stdin_fd = pipe1[1];
        proc->stdout_fd = pipe2[0];
        proc->stderr_fd = pipe3[0];
    }

    // nonblocking
    if (fcntl(proc->stdout_fd, F_SETFL, O_NONBLOCK) || fcntl(proc->stderr_fd, F_SETFL, O_NONBLOCK) || fcntl(proc->stdin_fd, F_SETFL, O_NONBLOCK)) {
        dr_fprintf(STDERR, "Failed to set stdio to nonblocking\n");
        dr_abort();
    }
}

// NOTE: This is called from thread_init_event on the main app thread
void pyda_prepare_io(pyda_process *proc) {
    // This sets up three new FDs for Pyda to
    // direct its output to. We set stdin/out/err to
    // the new FDs here, which occurs prior to Python startup
    //
    // Thus, Python will also use these new fds by default.

    int orig_in = dup(0);
    int orig_out = dup(1);
    int orig_err = dup(2);

    stdin = fdopen(orig_in, "r");
    stdout = fdopen(orig_out, "w");
    stderr = fdopen(orig_err, "w");

    our_stderr = orig_err;
}

static void free_context(void *ptr) {
    dr_global_free(ptr, sizeof(dr_mcontext_t));
}

pyda_thread* pyda_mk_thread(pyda_process *proc) {
    ABORT_IF_NODYNAMORIO;

    pyda_thread *thread = dr_global_alloc(sizeof(pyda_thread));
    pthread_condattr_t condattr;
    pthread_condattr_init(&condattr);
    int ret;

#ifdef LINUX
    if ((ret = pthread_condattr_setpshared(&condattr, PTHREAD_PROCESS_SHARED))) {
        dr_fprintf(STDERR, "pthread_condattr_setpshared failed: %d\n", ret);
        dr_abort();
    }
#endif // LINUX
    if ((ret = pthread_cond_init(&thread->resume_cond, &condattr))) {
        dr_fprintf(STDERR, "pthread_cond_init failed %d\n", ret);
        dr_abort();
    }

    if (pthread_cond_init(&thread->break_cond, &condattr)) {
        dr_fprintf(STDERR, "pthread_cond_init failed\n");
        dr_abort();
    }

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL);
#ifdef LINUX
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
#endif
    pthread_mutex_init(&thread->mutex, &attr);

    // Start with it locked...
    pthread_mutex_lock(&thread->mutex);

    thread->python_yielded = 0;
    thread->app_yielded = 0;
    thread->proc = proc;

    dr_atomic_add32_return_sum(&thread->proc->refcount, 1);

    thread->yield_count = 0;

    static volatile int tid = 0;
    thread->tid = dr_atomic_add32_return_sum(&tid, 1);
    thread->rip_updated_in_python = 0;
    thread->skip_next_hook = 0;
    thread->python_exited = 0;
    thread->app_exited = 0;
    thread->errored = 0;
    thread->python_blocked_on_io = 0;
    thread->run_until = 0;
    thread->signal = 0;
    thread->dirty_run_until = 0;
    thread->flush_ts = proc->flush_count;

    drvector_init(&thread->context_stack, 0, true, free_context);
    drvector_init(&thread->hook_update_queue, 0, true, NULL);

    drvector_append(&proc->threads, thread);
    drvector_append(&proc->thread_run_untils, NULL);

    thread->expr_builder = NULL;

    memset(thread->scratch_region, 0xef, sizeof(thread->scratch_region));

    // PyErr_SetString(PyExc_RuntimeError, "OK");
    return thread;
}

void pyda_process_destroy(pyda_process *p) {
    // We must be holding the GIL lock so we can drop the refs
    if (PyGILState_Check()) {
        DEBUG_PRINTF("pyda_process_destroy already holds GIL.")
    }
    PyGILState_STATE gstate = PyGILState_Ensure();

    DEBUG_PRINTF("pyda_process_destroy\n");
    if (p->thread_init_hook)
        Py_DECREF(p->thread_init_hook);

    p->thread_init_hook = NULL;

    if (p->syscall_pre_hook)
        Py_DECREF(p->syscall_pre_hook);

    p->syscall_pre_hook = NULL;

    if (p->syscall_post_hook)
        Py_DECREF(p->syscall_post_hook);

    p->syscall_post_hook = NULL;

    if (p->module_load_hook)
        Py_DECREF(p->module_load_hook);

    p->module_load_hook = NULL;

    hashtable_delete(&p->callbacks);
    drvector_delete(&p->threads);
    drvector_delete(&p->thread_run_untils);

    dr_global_free(p, sizeof(pyda_process));

    PyGILState_Release(gstate);
}

void pyda_thread_destroy(pyda_thread *t) {
    DEBUG_PRINTF("pyda_thread_destroy for idx %d\n", t->tid);
    pthread_mutex_lock(&t->proc->refcount_mutex);

    int new_refcount = dr_atomic_add32_return_sum(&t->proc->refcount, -1);
    if (new_refcount == 0) {
        pyda_process_destroy(t->proc);
    } else {
        pthread_cond_signal(&t->proc->thread_exit_cond);
        pthread_mutex_unlock(&t->proc->refcount_mutex);
    }

    drvector_delete(&t->context_stack);
    drvector_delete(&t->hook_update_queue);

    dr_global_free(t, sizeof(pyda_thread));
}

void pyda_thread_destroy_last(pyda_thread *t) {
    // wait for this thread to be the final thread
    pthread_mutex_lock(&t->proc->refcount_mutex);
    while (t->proc->refcount > 1)
        pthread_cond_wait(&t->proc->thread_exit_cond, &t->proc->refcount_mutex);

    DEBUG_PRINTF("pyda_thread_destroy_last unblock\n")
    pthread_mutex_unlock(&t->proc->refcount_mutex);
    pyda_thread_destroy(t);
}

void pyda_yield_noblock(pyda_thread *t) {
    t->python_yielded = 1;
    pthread_mutex_lock(&t->mutex);
    pthread_cond_broadcast(&t->resume_cond);
    pthread_mutex_unlock(&t->mutex);
}

// yield from python to the executable
void pyda_yield(pyda_thread *t) {
    t->python_yielded = 1;
    t->yield_count++;

    // here we wait for the executable to signal

    pthread_mutex_lock(&t->mutex);
    pthread_cond_broadcast(&t->resume_cond);

    while (!t->app_yielded)
        pthread_cond_wait(&t->break_cond, &t->mutex);

    t->app_yielded = 0;
    pthread_mutex_unlock(&t->mutex);

}

void pyda_break_noblock(pyda_thread *t) {
    t->app_yielded = 1;
    pthread_mutex_lock(&t->mutex);
    pthread_cond_broadcast(&t->break_cond);
    pthread_mutex_unlock(&t->mutex);
}

// yield from the executable back to python
void pyda_break(pyda_thread *t) {
    t->app_yielded = 1;

    // Hack to tell dynamorio that dr_flush_region on another thread is OK
    // here -- this is not REALLY safe per the docs but we use
    // dr_redirect_execution so we *should* always return to a valid fragment...
    // dr_mark_safe_to_suspend(dr_get_current_drcontext(), true);

    // here we wait for the python to signal
    pthread_mutex_lock(&t->mutex);
    pthread_cond_broadcast(&t->break_cond);

    while (!t->python_yielded)
        pthread_cond_wait(&t->resume_cond, &t->mutex);

    // dr_mark_safe_to_suspend(dr_get_current_drcontext(), false);

    t->python_yielded = 0;
    pthread_mutex_unlock(&t->mutex);
}

void pyda_initial_break(pyda_thread *t) {
    // lock is already held
    while (!t->python_yielded)
        pthread_cond_wait(&t->resume_cond, &t->mutex);

    t->python_yielded = 0;
    pthread_mutex_unlock(&t->mutex);
}

PyObject *pyda_run_until(pyda_thread *proc, uint64_t addr) {
    DEBUG_PRINTF("run_until: %llx\n", addr);
    return NULL;
}

void pyda_add_hook(pyda_process *p, uint64_t addr, PyObject *callback, int callback_type, int needs_flush) {
    pyda_hook *cb = dr_global_alloc(sizeof(pyda_hook));
    cb->py_func = callback;
    cb->callback_type = callback_type;
    cb->addr = (void*)addr;
    cb->deleted = 0;

    Py_INCREF(callback);
    DEBUG_PRINTF("pyda_add_hook %p %p for %llx (type=%d)\n", cb, cb->py_func, addr, callback_type);

    if (!hashtable_add(&p->callbacks, (void*)addr, cb)) {
        dr_global_free(cb, sizeof(pyda_hook));
        dr_fprintf(STDERR, "Failed to add hook at %p\n", (void*)addr);
        dr_abort();
    }

    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);

    if (needs_flush)
        drvector_append(&t->hook_update_queue, (void*)cb);
}

void pyda_remove_hook(pyda_process *p, uint64_t addr) {
    // note: GIL is held here...
    pyda_hook *cb = pyda_get_callback(p, (void*)addr);
    if (cb) {
        hashtable_remove(&p->callbacks, (void*)addr);
        pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);

        if (dr_memory_is_readable((app_pc)addr, 1))
            drvector_append(&t->hook_update_queue, (void*)cb);

        // Here, we decref the python function and NULL it out.
        // But we can't free it yet (there are still refs in the code
        // cache).
        free_hook_step1(cb);
    }
}

void pyda_set_thread_init_hook(pyda_process *p, PyObject *callback) {
    // NOTE: GIL is held

    if (p->thread_init_hook)
        Py_DECREF(p->thread_init_hook);

    p->thread_init_hook = callback;
    Py_INCREF(callback);
}

void pyda_set_syscall_pre_hook(pyda_process *p, PyObject *callback) {
    // NOTE: GIL is held

    if (p->syscall_pre_hook)
        Py_DECREF(p->syscall_pre_hook);

    p->syscall_pre_hook = callback;
    Py_INCREF(callback);
}

void pyda_set_syscall_post_hook(pyda_process *p, PyObject *callback) {
    // NOTE: GIL is held

    if (p->syscall_post_hook)
        Py_DECREF(p->syscall_post_hook);

    p->syscall_post_hook = callback;
    Py_INCREF(callback);
}

void pyda_set_module_load_hook(pyda_process *p, PyObject *callback) {
    // NOTE: GIL is held

    if (p->module_load_hook)
        Py_DECREF(p->module_load_hook);

    p->module_load_hook = callback;
    Py_INCREF(callback);
}

int pyda_flush_hooks() {
    void *drcontext = dr_get_current_drcontext();
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    pyda_process *p = t->proc;

    int flushed = 0;
    if (t->dirty_run_until) {
        void *run_until = pyda_get_run_until(t);
        if (run_until) dr_flush_region((void*)run_until, 1);
        t->dirty_run_until = 0;
        flushed = 1;
    }

    if (t->hook_update_queue.entries) {
        flushed = 1;

        // Copy to temporary, alternate storage so we don't hold the lock
        // (note: hook_update_queue is only shared between one python/app thread pair)
        // XXX: The copy doesn't make a lot of sense anymore, we don't call dr_mark_safe_to_suspend anywhere?
        int entry_count = t->hook_update_queue.entries;
        void **tmp = dr_thread_alloc(drcontext, sizeof(void*) * entry_count);
        if (!tmp) {
            dr_fprintf(STDERR, "dr_thread_alloc failed");
            dr_abort();
        }
        memcpy(tmp, t->hook_update_queue.array, sizeof(void*) * entry_count);
        t->hook_update_queue.entries = 0;

        // Flush added/removed hooks
        for (int i=0; i<entry_count; i++) {
            pyda_hook *hook = (pyda_hook*)tmp[i];

            if (hook->deleted) {
                tmp[i] = NULL; // Ensure we do not double-flush or double-free.
                continue;
            }

            void *addr = hook->addr;
            DEBUG_PRINTF("dr_flush_region: %llx\n", addr);
            dr_flush_region(addr, 1);
            DEBUG_PRINTF("dr_flush_region end %llx\n", addr);

            if (hook->py_func == NULL) {
                // This hook was removed; Now that the hook refs are finally removed from code cache,
                // we can free the pyda_hook. Here we mark ->deleted
                // so that we don't try to free it again. This can occur if hook is added/removed
                // without flushing.
                hook->deleted = 1;
            }

            // race lol
            p->flush_count++;
        }

        for (int i=0; i<entry_count; i++) {
            pyda_hook *hook = (pyda_hook*)tmp[i];
            if (hook && hook->deleted) {
                // Free the hook itself.
                free_hook_step2(hook);
            }
        }

        dr_thread_free(drcontext, tmp, sizeof(void*) * entry_count);
    }

    if (t->flush_ts != p->flush_count) {
        // Require that dr_redirect_execution is used, since another thread may have flushed
        // us during the dr_mark_safe_to_suspend section in thread_prepare_for_python_entry
        //
        // note: I think right now other threads cannot flush us
        flushed = 1;
        t->flush_ts = p->flush_count;
    }


    return flushed;
}
pyda_hook* pyda_get_callback(pyda_process *p, void* addr) {
    pyda_hook *cb = (void*)hashtable_lookup(&p->callbacks, addr);
    return cb;  // Return callback regardless of type, let caller handle type checking
}

void *pyda_get_run_until(pyda_thread *t) {
    return (void*)t->run_until;
}

void pyda_set_run_until(pyda_thread *t, void *pc) {
    t->run_until = (uint64_t)pc;
    t->dirty_run_until = 1;
    drvector_set_entry(&t->proc->thread_run_untils, t->tid-1, pc);
    // NOTE: Will be flushed by pyda_break callers. Don't need to flush here.
}

void pyda_clear_run_until(pyda_thread *t) {
    uint64_t run_until = t->run_until;
    t->run_until = 0;
    t->dirty_run_until = 1;
    drvector_set_entry(&t->proc->thread_run_untils, t->tid-1, NULL);

    if (run_until)
        dr_flush_region((void*)run_until, 1);
}

int pyda_check_run_until(pyda_process *proc, void *test_pc) {
    // Unlocked for performance.
    for (int i=0; i<proc->thread_run_untils.entries; i++) {
        if (test_pc == proc->thread_run_untils.array[i]) return 1;
    }
    return 0;
}

static void thread_prepare_for_python_entry(PyGILState_STATE *gstate, pyda_thread *t, void* pc) {
    if (gstate) {
        // HACK: dr_mark_safe_to_suspend is not allowed in a cleancall, per the docs.
        // We sortof get away with this because we check later to see if any flushes
        // occurred during this period, and force a dr_redirect_execution if they did.
        t->flush_ts = t->proc->flush_count;

        // dr_mark_safe_to_suspend(dr_get_current_drcontext(), true);
        *gstate = PyGILState_Ensure();
        // dr_mark_safe_to_suspend(dr_get_current_drcontext(), false);
    }

    void *drcontext = dr_get_current_drcontext();
    t->cur_context.size = sizeof(dr_mcontext_t);
    t->cur_context.flags = DR_MC_ALL; // dr_redirect_execution requires it
    dr_get_mcontext(drcontext, &t->cur_context);

    if (pc)
        t->cur_context.pc = (app_pc)pc;

    t->rip_updated_in_python = 0;
}

// NOTE: This is called without the GIL held!
static void thread_prepare_for_python_return(pyda_thread *t, void* hook_addr) {
    void *drcontext = dr_get_current_drcontext();

    // Syscall hooks are not allowed to modify PC and we not allow modifying hooks
    if (!hook_addr) {
        if (t->rip_updated_in_python) {
            dr_fprintf(STDERR, "\n[Pyda] ERROR: Syscall hooks are not allowed to modify PC. Skipping future hooks.\n");
            dr_flush_file(STDERR);
            t->errored = 1;
        }
        dr_set_mcontext(drcontext, &t->cur_context);
        if (t->hook_update_queue.entries > 0) {
            dr_fprintf(STDERR, "\n[Pyda] WARN: Hooks should not be modified in a syscall. This is UB, continuing.\n");
        }
        return;
    }

    if (t->cur_context.pc == (app_pc)hook_addr && t->rip_updated_in_python) {
        dr_fprintf(STDERR, "\n[Pyda] ERROR: Hook updated RIP to the same address. This is UB. Skipping future hooks.\n");
        dr_flush_file(STDERR);
        t->errored = 1;
    }

    if (pyda_flush_hooks() || t->rip_updated_in_python) {
        // NOTE: We are not holding any locks here... it's possible that some other thread will remove the hook we're executing right
        // now... the "best we can do for now" to avoid infinite loop is to detect that we are returning to the same spot,
        // and to skip the hook the next time.
        if (t->cur_context.pc == hook_addr && (pyda_get_callback(t->proc, hook_addr) || pyda_get_run_until(t) == hook_addr)) {
            t->skip_next_hook = 1;
            dr_flush_file(STDERR);
        }
        // we need to call dr_redirect_execution
        dr_redirect_execution(&t->cur_context);
    } else {
        dr_set_mcontext(drcontext, &t->cur_context);
    }
}

void pyda_hook_cleancall(pyda_hook *cb) {
    PyGILState_STATE gstate;
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);

    if (t->skip_next_hook) {
        t->skip_next_hook = 0;
        return;
    }

    if (t->errored) return;

    DEBUG_PRINTF("cleancall %p %p %p tid=%d\n", cb->addr, cb->py_func, t, dr_get_thread_id(dr_get_current_drcontext()));
    thread_prepare_for_python_entry(&gstate, t, cb->addr);
    DEBUG_PRINTF("cleancall LOCKED %p %p %p\n", cb->addr, cb->py_func, t);

    if (cb->py_func) { // Can be NULL if hook was already removed, but hasn't been flushed from code cache yet.
        PyObject *result = PyObject_CallFunctionObjArgs(cb->py_func, t->proc->py_obj, NULL);

        if (result == NULL) {
            dr_fprintf(STDERR, "\n[Pyda] ERROR: Hook call failed. Skipping future hooks on thread %d\n", t->tid);

            dr_flush_file(STDERR);
            t->errored = 1;
            PyErr_Print();
            dr_fprintf(STDERR, "\n");
            // dr_abort();
            if (getenv("PYDA_ABORT_ON_ERROR") && getenv("PYDA_ABORT_ON_ERROR")[0] == '1') {
                dr_fprintf(STDERR, "\n[Pyda] ABORTING (will crash now)\n");
                *(int*)(1) = 1;
            }
        } else {
            Py_DECREF(result);
        }

        DEBUG_PRINTF("cleancall ret %p %p %p\n", cb, cb->py_func, t);
    }

    PyGILState_Release(gstate);

    // If this also happens to be the run_until target for this thread,
    // we deal with that here (instead of inserting two hooks)
    if (!t->python_exited && cb->addr == pyda_get_run_until(t)) {
        // It is UB to modify PC in a hook that is also the run_until target
        if (t->rip_updated_in_python) {
            dr_fprintf(STDERR, "\n[Pyda] ERROR: Hook updated RIP, but run_until target is hit. This is UB. Continuing.");
            dr_flush_file(STDERR);
            t->errored = 1;
        }

        // Clear the run_until flag and flush the block
        pyda_clear_run_until(t);

        // Wait for Python to yield back to us
        pyda_break(t);
    }

    thread_prepare_for_python_return(t, cb->addr); // MAY NOT RETURN
}

int pyda_hook_syscall(int syscall_num, int is_pre) {
    PyGILState_STATE gstate;
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    if (t->errored) return 1;

    if (is_pre == 0 && (syscall_num == SYS_read || syscall_num == SYS_write) && t->python_blocked_on_io) { // read/write
        t->python_blocked_on_io = 0;
        thread_prepare_for_python_entry(NULL, t, NULL);
        pyda_break(t);
        thread_prepare_for_python_return(t, NULL); // (note: guaranteed to return)

        if (t->errored) return 1;
    }

    PyObject *hook = (is_pre ? t->proc->syscall_pre_hook : t->proc->syscall_post_hook);
    if (!hook) return 1;

    thread_prepare_for_python_entry(&gstate, t, NULL);

    DEBUG_PRINTF("syscall %d pre %d\n", syscall_num, is_pre);

    int should_run = 1;

    PyObject *syscall_num_obj = PyLong_FromLong(syscall_num);
    PyObject *result = PyObject_CallFunctionObjArgs(hook, t->proc->py_obj, syscall_num_obj, NULL);

    Py_DECREF(syscall_num_obj);

    if (result == NULL) {
        dr_fprintf(STDERR, "\n[Pyda] ERROR: Syscall hook call failed. Skipping future hooks on thread %d\n", t->tid);
        dr_flush_file(STDERR);
        t->errored = 1;
        PyErr_Print();
        dr_fprintf(STDERR, "\n");
    } else if (is_pre && PyBool_Check(result)) {
        // Should run
        should_run = PyObject_IsTrue(result);
        DEBUG_PRINTF("syscall pre_hook returned %d\n", should_run);
    } else {
        Py_DECREF(result);
        DEBUG_PRINTF("syscall hook returned non-bool\n");
    }

    DEBUG_PRINTF("syscall ret %d pre %d\n", syscall_num, is_pre);
    PyGILState_Release(gstate);
    thread_prepare_for_python_return(t, NULL);

    return should_run;
}

void pyda_hook_module_load(const char *module_path) {
    PyGILState_STATE gstate;
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    if (t->errored) return;

    PyObject *hook = t->proc->module_load_hook;
    if (!hook) return;

    thread_prepare_for_python_entry(&gstate, t, NULL);

    DEBUG_PRINTF("module_load %s\n", module_path);

    PyObject *module_path_obj = PyUnicode_FromString(module_path);
    PyObject *result = PyObject_CallFunctionObjArgs(hook, t->proc->py_obj, module_path_obj, NULL);

    Py_DECREF(module_path_obj);

    if (result == NULL) {
        dr_fprintf(STDERR, "\n[Pyda] ERROR: Module load hook call failed. Skipping future hooks on thread %d\n", t->tid);
        dr_flush_file(STDERR);
        t->errored = 1;
        PyErr_Print();
        dr_fprintf(STDERR, "\n");
    } else {
        Py_DECREF(result);
    }

    DEBUG_PRINTF("module_load ret %s\n", module_path);
    PyGILState_Release(gstate);
    thread_prepare_for_python_return(t, NULL);
}

void pyda_hook_rununtil_reached(void *pc) {
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    if (t->errored || t->python_exited) return;
    if (t->skip_next_hook) {
        t->skip_next_hook = 0;
        return;
    }

    if (pyda_get_run_until(t) == pc) {
        thread_prepare_for_python_entry(NULL, t, pc);

        // Clear the run_until flag and flush the block
        pyda_clear_run_until(t);

        // Wait for Python to yield back to us
        pyda_break(t);
        thread_prepare_for_python_return(t, pc); // MAY NOT RETURN
    } else {
        // This can actually happen in two cases:
        // 1. The code cache entry was not flushed (BUG in Pyda!) after a run_until
        // 2. Another thread set this run_until hook (This is fine.)
        DEBUG_PRINTF("STALE run_until reached: %llx\n", pc);
    }
}

int pyda_push_context(pyda_thread *t) {
    if (t->context_stack.entries >= CONTEXT_STACK_LIMIT) return 0; // arbitrary limit

    dr_mcontext_t *new = dr_global_alloc(sizeof(dr_mcontext_t));
    memcpy(new, &t->cur_context, sizeof(dr_mcontext_t));
    drvector_append(&t->context_stack, new);
    return 1;
}

int pyda_pop_context(pyda_thread *t) {
    drvector_lock(&t->context_stack);
    if (t->context_stack.entries == 0) return 0;
    t->context_stack.entries--;
    memcpy(&t->cur_context, t->context_stack.array[t->context_stack.entries], sizeof(dr_mcontext_t));
    free_context(t->context_stack.array[t->context_stack.entries]);
    drvector_unlock(&t->context_stack);
    return 1;
}

extern PyTypeObject PydaExprBuilder_Type;

void pyda_handle_advanced_hook(instrlist_t *bb, instr_t *instr, pyda_hook *callback) {
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    
    // Initialize expression builder
    t->expr_builder = exprbuilder_init();

    // Create Python wrapper for builder
    PyGILState_STATE gstate = PyGILState_Ensure();
    
    PydaExprBuilder *py_builder = PyObject_New(PydaExprBuilder, &PydaExprBuilder_Type);
    if (!py_builder) {
        PyErr_Print();
        goto cleanup;
    }
    py_builder->builder = t->expr_builder;

    // Call the Python callback
    PyObject *result = PyObject_CallFunctionObjArgs(callback->py_func, py_builder, NULL);
    if (result) {
        Py_DECREF(result);
    } else {
        dr_fprintf(STDERR, "Error in advanced hook at %p\n", callback->addr);
        PyErr_Print();
    }

    Py_DECREF(py_builder);

    exprbuilder_compile(t->expr_builder, bb, instr, 0);
    DEBUG_PRINTF("Compiled advanced hook at %p\n", callback->addr);

cleanup:
    // Cleanup
    exprbuilder_delete(t->expr_builder);
    t->expr_builder = NULL;
    
    PyGILState_Release(gstate);
}

#endif
