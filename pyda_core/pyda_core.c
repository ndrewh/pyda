
#include "pyda_core.h"
#include "pyda_threads.h"
#include "util.h"
#include <fcntl.h>
#include <pty.h>



#ifndef PYDA_DYNAMORIO_CLIENT

pyda_process* pyda_mk_process() {
    // TODO: We might be able to use this to fork and launch the process
    // (in which the entire python file will be reparsed...)
    ABORT_IF_NODYNAMORIO;
}

#else
#include "dr_api.h"

static void free_hook(void *data) {
    pyda_hook *hook = (pyda_hook*)data;
    Py_DECREF(hook->py_func);
    hook->py_func = NULL;
    dr_global_free(hook, sizeof(pyda_hook));
}

static void thread_prepare_for_python_entry(PyGILState_STATE *gstate, pyda_thread *t, void* pc);
static void thread_prepare_for_python_return(PyGILState_STATE *gstate, pyda_thread *t, void* hook_addr);


pyda_process* pyda_mk_process() {
    ABORT_IF_NODYNAMORIO;

    pyda_process *proc = dr_global_alloc(sizeof(pyda_process));
    proc->refcount = 0; // xxx: will be incremented to 1 by first pyda_mk_thread
    proc->dirty_hooks = 0;
    drvector_init(&proc->threads, 0, true, NULL);
    drvector_init(&proc->thread_run_untils, 0, true, NULL);

    proc->main_thread = pyda_mk_thread(proc);
    hashtable_init_ex(&proc->callbacks, 4, HASH_INTPTR, false, false, free_hook, NULL, NULL);

    proc->thread_init_hook = NULL;
    proc->syscall_pre_hook = NULL;
    proc->syscall_post_hook = NULL;
    proc->py_obj = NULL;

    // Setup locks, etc.
    pthread_condattr_t condattr;
    int ret;
    if (ret = pthread_condattr_setpshared(&condattr, PTHREAD_PROCESS_SHARED)) {
        dr_fprintf(STDERR, "pthread_condattr_setpshared failed: %d\n", ret);
        dr_abort();
    }
    if (ret = pthread_cond_init(&proc->thread_exit_cond, &condattr)) {
        dr_fprintf(STDERR, "pthread_cond_init failed %d\n", ret);
        dr_abort();
    }

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    if (ret = pthread_mutex_init(&proc->refcount_mutex, &attr)) {
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

        dup2(pipe1[0], 0);
        dup2(pipe2[1], 1);
        dup2(pipe3[1], 2);

        proc->stdin_fd = pipe1[1];
        proc->stdout_fd = pipe2[0];
        proc->stderr_fd = pipe3[0];
    }

    // nonblocking
    if (fcntl(proc->stdout_fd, F_SETFL, O_NONBLOCK) || fcntl(proc->stderr_fd, F_SETFL, O_NONBLOCK)) {
        dr_fprintf(STDERR, "Failed to set stdout to nonblocking\n");
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

pyda_thread* pyda_mk_thread(pyda_process *proc) {
    ABORT_IF_NODYNAMORIO;

    pyda_thread *thread = dr_global_alloc(sizeof(pyda_thread));
    pthread_condattr_t condattr;
    pthread_condattr_init(&condattr);
    int ret;
    if (ret = pthread_condattr_setpshared(&condattr, PTHREAD_PROCESS_SHARED)) {
        dr_fprintf(STDERR, "pthread_condattr_setpshared failed: %d\n", ret);
        dr_abort();
    }
    if (ret = pthread_cond_init(&thread->resume_cond, &condattr)) {
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
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&thread->mutex, &attr);

    // Start with it locked...
    pthread_mutex_lock(&thread->mutex);

    thread->python_yielded = 0;
    thread->app_yielded = 0;
    thread->proc = proc;

    dr_atomic_add32_return_sum(&thread->proc->refcount, 1);

    thread->yield_count = 0;

    static volatile unsigned int tid = 0;
    thread->tid = dr_atomic_add32_return_sum(&tid, 1);
    thread->rip_updated_in_python = 0;
    thread->skip_next_hook = 0;
    thread->python_exited = 0;
    thread->app_exited = 0;
    thread->errored = 0;
    thread->python_blocked_on_io = 0;
    thread->run_until = 0;

    drvector_append(&proc->threads, thread);
    drvector_append(&proc->thread_run_untils, NULL);

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

    hashtable_delete(&p->callbacks);
    drvector_delete(&p->threads);
    drvector_delete(&p->thread_run_untils);

    dr_global_free(p, sizeof(pyda_process));

    PyGILState_Release(gstate);
}

void pyda_thread_destroy(pyda_thread *t) {
    pthread_mutex_lock(&t->proc->refcount_mutex);

    int new_refcount = dr_atomic_add32_return_sum(&t->proc->refcount, -1);
    if (new_refcount == 0) {
        pyda_process_destroy(t->proc);
    } else {
        pthread_cond_signal(&t->proc->thread_exit_cond);
        pthread_mutex_unlock(&t->proc->refcount_mutex);
    }

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
    pthread_cond_signal(&t->resume_cond);
    pthread_mutex_unlock(&t->mutex);
}

// yield from python to the executable
void pyda_yield(pyda_thread *t) {
    t->python_yielded = 1;
    t->yield_count++;

    // here we wait for the executable to signal
    // dr_set_safe_for_sync(false);

    pthread_mutex_lock(&t->mutex);
    pthread_cond_signal(&t->resume_cond);

    while (!t->app_yielded)
        pthread_cond_wait(&t->break_cond, &t->mutex);

    t->app_yielded = 0;
    pthread_mutex_unlock(&t->mutex);

    // dr_set_safe_for_sync(true);
}

void pyda_break_noblock(pyda_thread *t) {
    t->app_yielded = 1;
    pthread_mutex_lock(&t->mutex);
    pthread_cond_signal(&t->break_cond);
    pthread_mutex_unlock(&t->mutex);
}

// yield from the executable back to python
void pyda_break(pyda_thread *t) {
    t->app_yielded = 1;

    // here we wait for the python to signal
    // dr_set_safe_for_sync(false);

    pthread_mutex_lock(&t->mutex);
    pthread_cond_signal(&t->break_cond);

    while (!t->python_yielded)
        pthread_cond_wait(&t->resume_cond, &t->mutex);

    t->python_yielded = 0;
    pthread_mutex_unlock(&t->mutex);
    // dr_set_safe_for_sync(true);
}

void pyda_initial_break(pyda_thread *t) {
    // lock is already held
    // dr_set_safe_for_sync(false);
    while (!t->python_yielded)
        pthread_cond_wait(&t->resume_cond, &t->mutex);

    t->python_yielded = 0;
    pthread_mutex_unlock(&t->mutex);
    // dr_set_safe_for_sync(true);
}

PyObject *pyda_run_until(pyda_thread *proc, uint64_t addr) {
    DEBUG_PRINTF("run_until: %llx\n", addr);
    return NULL;
}

void pyda_add_hook(pyda_process *t, uint64_t addr, PyObject *callback) {
    pyda_hook *cb = dr_global_alloc(sizeof(pyda_hook));
    cb->py_func = callback;

    Py_INCREF(callback);
    DEBUG_PRINTF("pyda_add_hook %p %p\n", cb, cb->py_func);

    cb->callback_type = 0;
    cb->addr = (void*)addr;


    // void *drcontext = dr_get_current_drcontext();
    // dr_where_am_i_t whereami = dr_where_am_i(drcontext, (void*)addr, NULL);
    // DEBUG_PRINTF("Hook is in %lu\n", whereami);

    if (!hashtable_add(&t->callbacks, (void*)addr, cb)) {
        dr_global_free(cb, sizeof(pyda_hook));
        dr_fprintf(STDERR, "Failed to add hook at %p\n", (void*)addr);
        dr_abort();
    }

    t->dirty_hooks = 1;
}

void pyda_remove_hook(pyda_process *p, uint64_t addr) {
    hashtable_remove(&p->callbacks, (void*)addr);
    p->dirty_hooks = 1;
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

static void flush_hook(void *hook) {
    pyda_hook *cb = (pyda_hook*)hook;
    if (cb->callback_type == 0) {
        DEBUG_PRINTF("dr_flush_region: %llx\n", (void*)cb->addr);
        dr_flush_region((void*)cb->addr, 1);
        DEBUG_PRINTF("dr_flush_region end\n");
    }

}

int pyda_flush_hooks() {
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    pyda_process *p = t->proc;

    int flushed = 0;
    if (t->dirty_run_until) {
        void *run_until = pyda_get_run_until(t);
        if (run_until) dr_flush_region((void*)run_until, 1);
        t->dirty_run_until = 0;
        flushed = 1;
    }

    if (p->dirty_hooks) {
        hashtable_apply_to_all_payloads(&p->callbacks, flush_hook);
        p->dirty_hooks = 0;
        flushed = 1;
    }

    return flushed;
}
pyda_hook* pyda_get_callback(pyda_process *p, void* addr) {
    pyda_hook *cb = (void*)hashtable_lookup(&p->callbacks, addr);

    if (cb && cb->callback_type == 0) {
        return cb;
    }

    return NULL;
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

    dr_flush_region((void*)run_until, 1);
}

int pyda_check_run_until(pyda_process *proc, void *test_pc) {
    // Unlocked for performance.
    for (int i=0; i<proc->thread_run_untils.capacity; i++) {
        if (test_pc == proc->thread_run_untils.array[i]) return 1;
    }
    return 0;
}

static void thread_prepare_for_python_entry(PyGILState_STATE *gstate, pyda_thread *t, void* pc) {
    if (gstate) *gstate = PyGILState_Ensure();

    void *drcontext = dr_get_current_drcontext();
    t->cur_context.size = sizeof(dr_mcontext_t);
    t->cur_context.flags = DR_MC_ALL; // dr_redirect_execution requires it
    dr_get_mcontext(drcontext, &t->cur_context);

    if (pc)
        t->cur_context.pc = (app_pc)pc;

    t->rip_updated_in_python = 0;
}

static void thread_prepare_for_python_return(PyGILState_STATE *gstate, pyda_thread *t, void* hook_addr) {
    void *drcontext = dr_get_current_drcontext();

    // Syscall hooks are not allowed to modify PC
    if (!hook_addr) {
        if (t->rip_updated_in_python) {
            dr_fprintf(STDERR, "\n[Pyda] ERROR: Syscall hooks are not allowed to modify PC. Skipping future hooks.\n");
            dr_flush_file(STDERR);
            t->errored = 1;
        }
        dr_set_mcontext(drcontext, &t->cur_context);
        if (t->proc->dirty_hooks) {
            dr_fprintf(STDERR, "\n[Pyda] WARN: Hooks should not be modified in a syscall. This is UB, continuing.\n");
        }
        if (gstate) PyGILState_Release(*gstate);
        return;
    }

    if (t->cur_context.pc == (app_pc)hook_addr && t->rip_updated_in_python) {
        dr_fprintf(STDERR, "\n[Pyda] ERROR: Hook updated RIP to the same address. This is UB. Skipping future hooks.\n");
        dr_flush_file(STDERR);
        t->errored = 1;
    }

    if (pyda_flush_hooks() || t->rip_updated_in_python) {
        // XXX: We might not be holding the GIL here (in run_until case) -- is hash-table locked?
        if (t->cur_context.pc == hook_addr && (pyda_get_callback(t->proc, hook_addr) || pyda_get_run_until(t) == hook_addr)) {
            t->skip_next_hook = 1;
        }
        // we need to call dr_redirect_execution
        if (gstate) PyGILState_Release(*gstate);
        dr_redirect_execution(&t->cur_context);
    } else {
        dr_set_mcontext(drcontext, &t->cur_context);
        if (gstate) PyGILState_Release(*gstate);
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

    thread_prepare_for_python_entry(&gstate, t, cb->addr);

    DEBUG_PRINTF("cleancall %p %p %p\n", cb, cb->py_func, t);

    PyObject *result = PyObject_CallFunctionObjArgs(cb->py_func, t->proc->py_obj, NULL);

    if (result == NULL) {
        dr_fprintf(STDERR, "\n[Pyda] ERROR: Hook call failed. Skipping future hooks on thread %d\n", t->tid);
        dr_flush_file(STDERR);
        t->errored = 1;
        PyErr_Print();
        dr_fprintf(STDERR, "\n");
        // dr_abort();
    } else {
        Py_DECREF(result);
    }

    DEBUG_PRINTF("cleancall ret %p %p %p\n", cb, cb->py_func, t);

    PyGILState_Release(gstate);

    // If this also happens to be the run_until target for this thread,
    // we deal with that here (instead of inserting two hooks)
    if (cb->addr == pyda_get_run_until(t)) {
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

    thread_prepare_for_python_return(NULL, t, cb->addr); // MAY NOT RETURN
}

int pyda_hook_syscall(int syscall_num, int is_pre) {
    PyGILState_STATE gstate;
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    if (t->errored) return 1;

    if (is_pre == 0 && (syscall_num == 0 || syscall_num == 1) && t->python_blocked_on_io) { // read/write
        t->python_blocked_on_io = 0;
        thread_prepare_for_python_entry(NULL, t, NULL);
        pyda_break(t);
        thread_prepare_for_python_return(NULL, t, NULL);

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
    thread_prepare_for_python_return(&gstate, t, NULL);

    return should_run;
}

void pyda_hook_rununtil_reached(void *pc) {
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    if (t->errored) return;
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
        thread_prepare_for_python_return(NULL, t, pc); // MAY NOT RETURN
    } else {
        // This can actually happen in two cases:
        // 1. The code cache entry was not flushed (BUG in Pyda!) after a run_until
        // 2. Another thread set this run_until hook (This is fine.)
        DEBUG_PRINTF("STALE run_until reached: %llx\n", pc);
    }
}

#endif