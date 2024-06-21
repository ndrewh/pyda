
#ifndef PYDA_CORE_H
#define PYDA_CORE_H

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#define Py_BUILD_CORE
#include <internal/pycore_condvar.h>
#undef Py_BUILD_CORE

#ifdef PYDA_DYNAMORIO_CLIENT
#include <dr_api.h>
#endif

extern int is_dynamorio_running;
typedef struct pyda_hook_s pyda_hook;
typedef struct pyda_thread_s pyda_thread;
typedef struct pyda_process_s pyda_process;

// Since we have multiple threads running, we need to keep track of
// which one is holding the GIL.

struct pyda_hook_s {
    PyObject *py_func;
    int callback_type;
    void *addr;

    pyda_hook *next;
};

struct pyda_process_s {
    pyda_hook *callbacks;
    int dirty_hooks;
    int refcount;

    pyda_thread *main_thread;
    PyObject *thread_init_hook;
    PyObject *py_obj;

    pthread_cond_t thread_exit_cond;
    pthread_mutex_t refcount_mutex;

    void* entrypoint;
};

struct pyda_thread_s {
    unsigned long tid;

    pthread_cond_t resume_cond;
    pthread_cond_t break_cond;
    pthread_mutex_t mutex;

    int python_yielded, app_yielded;

    pyda_process *proc;
    // PyObject *py_obj;

    int rip_updated_in_cleancall;
    int skip_next_hook;
    int python_exited;
    int yield_count;

    int errored;

#ifdef PYDA_DYNAMORIO_CLIENT
    dr_mcontext_t cur_context;
#endif
};

pyda_process* pyda_mk_process();
pyda_thread* pyda_mk_thread(pyda_process*);

void pyda_process_destroy(pyda_process *p);
void pyda_thread_destroy(pyda_thread *t);
void pyda_thread_destroy_last(pyda_thread *t);

PyObject *pyda_run_until(pyda_thread *, uint64_t addr);

// yield from python to the executable
void pyda_yield(pyda_thread *t);
void pyda_yield_noblock(pyda_thread *t); // used when thread entry hook returns, we don't need to return to python.

// break from the executable to python
void pyda_break(pyda_thread *t);
void pyda_break_noblock(pyda_thread *t); // used when app exits, no need to return to it.

void pyda_initial_break(pyda_thread *t);
void pyda_add_hook(pyda_process *p, uint64_t addr, PyObject *callback);
void pyda_remove_hook(pyda_process *p, uint64_t addr);
void pyda_set_thread_init_hook(pyda_process *p, PyObject *callback);
pyda_hook* pyda_get_callback(pyda_process *p, void* addr);

// These can only be called from application threads
int pyda_flush_hooks();
void pyda_hook_cleancall(pyda_hook *cb);


#ifndef PYDA_DYNAMORIO_CLIENT

#define ABORT_IF_NODYNAMORIO {\
    PyErr_SetString(PyExc_RuntimeError, "This script must be run through the pyda CLI"); \
    return NULL;\
}

#else

#define ABORT_IF_NODYNAMORIO if (!is_dynamorio_running) {\
    PyErr_SetString(PyExc_RuntimeError, "This script must be run through the pyda CLI"); \
    return NULL;\
}

#endif


#endif // PYDA_CORE_H
