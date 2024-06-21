
#include "pyda_core.h"
#include "pyda_threads.h"
#include "util.h"

#ifndef PYDA_DYNAMORIO_CLIENT

pyda_process* pyda_mk_process() {
    // TODO: We might be able to use this to fork and launch the process
    // (in which the entire python file will be reparsed...)
    ABORT_IF_NODYNAMORIO;
}

#else
#include "dr_api.h"

pyda_process* pyda_mk_process() {
    ABORT_IF_NODYNAMORIO;

    pyda_process *proc = dr_global_alloc(sizeof(pyda_process));
    proc->refcount = 0; // xxx: will be incremented to 1 by first pyda_mk_thread
    proc->dirty_hooks = 0;
    proc->main_thread = pyda_mk_thread(proc);
    proc->callbacks = NULL;
    proc->thread_init_hook = NULL;
    proc->py_obj = NULL;

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
    return proc;
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
    thread->errored = 0;

    // PyErr_SetString(PyExc_RuntimeError, "OK");
    return thread;
}

void pyda_process_destroy(pyda_process *p) {
    // We must be holding the GIL lock so we can drop the refs
    PyGILState_STATE gstate = PyGILState_Ensure();

    DEBUG_PRINTF("pyda_process_destroy\n");
    if (p->thread_init_hook)
        Py_DECREF(p->thread_init_hook);
    
    p->thread_init_hook = NULL;

    pyda_hook *cb = p->callbacks;
    while (cb) {
        Py_DECREF(cb->py_func);
        cb->py_func = NULL;

        void *del = cb;
        cb = cb->next;

        dr_global_free(del, sizeof(pyda_hook));
    }
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
    cb->next = t->callbacks;
    cb->addr = (void*)addr;


    // void *drcontext = dr_get_current_drcontext();
    // dr_where_am_i_t whereami = dr_where_am_i(drcontext, (void*)addr, NULL);
    // DEBUG_PRINTF("Hook is in %lu\n", whereami);

    t->callbacks = cb;
    t->dirty_hooks = 1;
}

void pyda_remove_hook(pyda_process *p, uint64_t addr) {
    pyda_hook **cb = &p->callbacks;
    while (*cb) {
        if ((*cb)->callback_type == 0 && (*cb)->addr == (void*)addr) {
            *cb = (*cb)->next;
            break;
        }
        cb = &(*cb)->next;
    }

    p->dirty_hooks = 1;
}

void pyda_set_thread_init_hook(pyda_process *p, PyObject *callback) {
    // NOTE: GIL is held

    if (p->thread_init_hook)
        Py_DECREF(p->thread_init_hook);

    p->thread_init_hook = callback;
    Py_INCREF(callback);
}

int pyda_flush_hooks() {
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    pyda_process *p = t->proc;
    if (!p->dirty_hooks) return 0;

    pyda_hook *cb = p->callbacks;
    while (cb) {
        if (cb->callback_type == 0) {
            DEBUG_PRINTF("dr_flush_region: %llx\n", (void*)cb->addr);
            dr_flush_region((void*)cb->addr, 1);
            DEBUG_PRINTF("dr_flush_region end\n");
        }
        cb = cb->next;
    }
    p->dirty_hooks = 0;
    return 1;
}
pyda_hook* pyda_get_callback(pyda_process *p, void* addr) {
    pyda_hook *cb = p->callbacks;
    while (cb) {
        if (cb->callback_type == 0 && cb->addr == addr)
            return cb;
        cb = cb->next;
    }
    return NULL;
}

void pyda_hook_cleancall(pyda_hook *cb) {
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    if (t->skip_next_hook) {
        t->skip_next_hook = 0;
        return;
    }

    if (t->errored) return;

    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();

    void *drcontext = dr_get_current_drcontext();
    t->cur_context.size = sizeof(dr_mcontext_t);
    t->cur_context.flags = DR_MC_ALL; // dr_redirect_execution requires it
    dr_get_mcontext(drcontext, &t->cur_context);
    t->cur_context.pc = (app_pc)cb->addr;
    t->rip_updated_in_cleancall = 0;

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

    if (t->cur_context.pc == (app_pc)cb->addr && t->rip_updated_in_cleancall) {
        if (t->rip_updated_in_cleancall) {
            dr_fprintf(STDERR, "\n[Pyda] Hook updated RIP to the same address. This is UB. Skipping future hooks.\n");
            dr_flush_file(STDERR);
            t->errored = 1;
            // dr_abort();
        }
    }

    if (pyda_flush_hooks() || t->rip_updated_in_cleancall) {
        if (t->cur_context.pc == cb->addr) {
            t->skip_next_hook = 1;
        }
        // we need to call dr_redirect_execution
        PyGILState_Release(gstate);
        dr_redirect_execution(&t->cur_context);
    } else {
        dr_set_mcontext(drcontext, &t->cur_context);
        PyGILState_Release(gstate);
    }
}

#endif