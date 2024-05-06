
#include "pyda_core.h"
#include "pyda_threads.h"
#include "util.h"

#ifndef PYDA_DYNAMORIO_CLIENT

pyda_thread* pyda_mk_process() {
    // TODO: We might be able to use this to fork and launch the process
    // (in which the entire python file will be reparsed...)
    ABORT_IF_NODYNAMORIO;
}

#else
#include "dr_api.h"

pyda_thread* pyda_mk_process() {
    ABORT_IF_NODYNAMORIO;

    pyda_thread *process = dr_global_alloc(sizeof(pyda_thread));
    pthread_cond_init(&process->resume_cond, 0);
    pthread_cond_init(&process->break_cond, 0);

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL);
    pthread_mutex_init(&process->mutex, &attr);

    // Start with it locked...
    pthread_mutex_lock(&process->mutex);

    process->python_yielded = 0;
    process->app_yielded = 0;
    process->callbacks = NULL;
    process->dirty_hooks = 0;
    process->refcount = 2;

    // PyErr_SetString(PyExc_RuntimeError, "OK");
    return process;
}

void pyda_process_destroy(pyda_thread *t) {
    ABORT_IF_NODYNAMORIO;

    if (--t->refcount > 0) return;

    pyda_hook *cb = t->callbacks;
    while (cb) {
        void *del = cb;
        cb = cb->next;
        dr_global_free(del, sizeof(pyda_hook));
    }
    dr_global_free(t, sizeof(pyda_thread));
}

// yield from python to the executable
void pyda_yield(pyda_thread *t) {
    t->python_yielded = 1;
    pthread_cond_signal(&t->resume_cond);
    DEBUG_PRINTF("pyda_yield\n");

    // here we wait for the executable to signal
    // dr_set_safe_for_sync(false);

    pthread_mutex_lock(&t->mutex);
    while (!t->app_yielded)
        pthread_cond_wait(&t->break_cond, &t->mutex);

    t->python_yielded = 0;
    pthread_mutex_unlock(&t->mutex);

    // dr_set_safe_for_sync(true);
}

// yield from the executable back to python
void pyda_break(pyda_thread *t) {
    t->app_yielded = 1;
    pthread_cond_signal(&t->break_cond);

    // here we wait for the python to signal
    // dr_set_safe_for_sync(false);

    pthread_mutex_lock(&t->mutex);
    while (!t->python_yielded)
        pthread_cond_wait(&t->resume_cond, &t->mutex);

    t->app_yielded = 0;
    pthread_mutex_unlock(&t->mutex);
    // dr_set_safe_for_sync(true);
}

void pyda_initial_break(pyda_thread *t) {
    // lock is already held
    // dr_set_safe_for_sync(false);
    while (!t->python_yielded)
        pthread_cond_wait(&t->resume_cond, &t->mutex);

    pthread_mutex_unlock(&t->mutex);
    // dr_set_safe_for_sync(true);
}

PyObject *pyda_run_until(pyda_thread *proc, uint64_t addr) {
    DEBUG_PRINTF("run_until: %llx\n", addr);
    return NULL;
}

void pyda_add_hook(pyda_thread *t, uint64_t addr, PyObject *callback) {
    pyda_hook *cb = dr_global_alloc(sizeof(pyda_hook));
    cb->py_func = callback;
    cb->callback_type = 0;
    cb->next = t->callbacks;
    cb->addr = (void*)addr;


    // void *drcontext = dr_get_current_drcontext();
    // dr_where_am_i_t whereami = dr_where_am_i(drcontext, (void*)addr, NULL);
    // DEBUG_PRINTF("Hook is in %lu\n", whereami);

    t->callbacks = cb;
    t->dirty_hooks = 1;
}

int pyda_flush_hooks() {
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    if (!t->dirty_hooks) return 0;

    pyda_hook *cb = t->callbacks;
    while (cb) {
        if (cb->callback_type == 0) {
            DEBUG_PRINTF("dr_flush_region: %llx\n", (void*)cb->addr);
            dr_flush_region((void*)cb->addr, 1);
            DEBUG_PRINTF("dr_flush_region end");
        }
        cb = cb->next;
    }
    t->dirty_hooks = 0;
    return 1;
}
pyda_hook* pyda_get_callback(pyda_thread *t, void* addr) {
    pyda_hook *cb = t->callbacks;
    while (cb) {
        if (cb->callback_type == 0 && cb->addr == addr)
            return cb;
        cb = cb->next;
    }
    return NULL;
}

void pyda_hook_cleancall(pyda_hook *cb) {
    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();

    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);

    void *drcontext = dr_get_current_drcontext();
    t->cur_context.size = sizeof(dr_mcontext_t);
    t->cur_context.flags = DR_MC_INTEGER | DR_MC_CONTROL; // assuming SIMD doesnt exist
    dr_get_mcontext(drcontext, &t->cur_context);
    t->cur_context.pc = cb->addr;

    PyObject *result = PyObject_CallFunctionObjArgs(cb->py_func, t->py_obj, PyLong_FromUnsignedLong((unsigned long)cb->addr), NULL);
    if (result == NULL) {
        PyErr_Print();
        dr_abort();
    }
    Py_DECREF(result);

    PyGILState_Release(gstate);
}

#endif