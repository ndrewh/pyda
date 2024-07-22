
#include "pyda_core.h"
#include "pyda_threads.h"
#include "util.h"
#include <fcntl.h>


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

pyda_process* pyda_mk_process() {
    ABORT_IF_NODYNAMORIO;

    pyda_process *proc = dr_global_alloc(sizeof(pyda_process));
    proc->refcount = 0; // xxx: will be incremented to 1 by first pyda_mk_thread
    proc->dirty_hooks = 0;
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
void pyda_capture_io(pyda_process *proc) {
    int orig_in = dup(0);
    int orig_out = dup(1);
    int orig_err = dup(2);

    int pipe1[2], pipe2[2], pipe3[2];
    if (pipe(pipe1) || pipe(pipe2) || pipe(pipe3)) {
        dr_fprintf(STDERR, "Failed to create pipes\n");
        dr_abort();
    }

    dup2(pipe1[0], 0);
    dup2(pipe2[1], 1);
    dup2(pipe3[1], 2);

    stdin = fdopen(orig_in, "r");
    stdout = fdopen(orig_out, "w");
    stderr = fdopen(orig_err, "w");

    proc->stdin_fd = pipe1[1];
    proc->stdout_fd = pipe2[0];
    proc->stderr_fd = pipe3[0];

    our_stderr = orig_err;

    // nonblocking
    if (fcntl(proc->stdout_fd, F_SETFL, O_NONBLOCK) || fcntl(proc->stderr_fd, F_SETFL, O_NONBLOCK)) {
        dr_fprintf(STDERR, "Failed to set stdout to nonblocking\n");
        dr_abort();
    }
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
    thread->rip_updated_in_cleancall = 0;
    thread->skip_next_hook = 0;
    thread->python_exited = 0;
    thread->app_exited = 0;
    thread->errored = 0;
    thread->python_blocked_on_io = 0;

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
    if (!p->dirty_hooks) return 0;

    hashtable_apply_to_all_payloads(&p->callbacks, flush_hook);
    p->dirty_hooks = 0;
    return 1;
}
pyda_hook* pyda_get_callback(pyda_process *p, void* addr) {
    pyda_hook *cb = (void*)hashtable_lookup(&p->callbacks, addr);

    if (cb && cb->callback_type == 0) {
        return cb;
    }

    return NULL;
}

static void thread_prepare_for_python_entry(PyGILState_STATE *gstate, pyda_thread *t, void* pc) {
    *gstate = PyGILState_Ensure();

    void *drcontext = dr_get_current_drcontext();
    t->cur_context.size = sizeof(dr_mcontext_t);
    t->cur_context.flags = DR_MC_ALL; // dr_redirect_execution requires it
    dr_get_mcontext(drcontext, &t->cur_context);

    if (pc)
        t->cur_context.pc = (app_pc)pc;

    t->rip_updated_in_cleancall = 0;
}

static void thread_prepare_for_python_return(PyGILState_STATE *gstate, pyda_thread *t, void* hook_addr) {
    void *drcontext = dr_get_current_drcontext();

    // Syscall hooks are not allowed to modify PC
    if (!hook_addr) {
        if (t->rip_updated_in_cleancall) {
            dr_fprintf(STDERR, "\n[Pyda] ERROR: Syscall hooks are not allowed to modify PC. Skipping future hooks.\n");
            dr_flush_file(STDERR);
            t->errored = 1;
        }
        dr_set_mcontext(drcontext, &t->cur_context);
        if (t->proc->dirty_hooks) {
            dr_fprintf(STDERR, "\n[Pyda] WARN: Hooks should not be modified in a syscall. This is UB, continuing.\n");
        }
        PyGILState_Release(*gstate);
        return;
    }

    if (t->cur_context.pc == (app_pc)hook_addr && t->rip_updated_in_cleancall) {
        if (t->rip_updated_in_cleancall) {
            dr_fprintf(STDERR, "\n[Pyda] ERROR: Hook updated RIP to the same address. This is UB. Skipping future hooks.\n");
            dr_flush_file(STDERR);
            t->errored = 1;
        }
    }

    if (pyda_flush_hooks() || t->rip_updated_in_cleancall) {
        if (t->cur_context.pc == hook_addr) {
            t->skip_next_hook = 1;
        }
        // we need to call dr_redirect_execution
        PyGILState_Release(*gstate);
        dr_redirect_execution(&t->cur_context);
    } else {
        dr_set_mcontext(drcontext, &t->cur_context);
        PyGILState_Release(*gstate);
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
    thread_prepare_for_python_return(&gstate, t, cb->addr);
}

int pyda_hook_syscall(int syscall_num, int is_pre) {
    PyGILState_STATE gstate;
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    if (t->errored) return 1;

    if (syscall_num == 1 && t->python_blocked_on_io) { // write
        t->python_blocked_on_io = 0;
        pyda_break(t);
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

#endif