
#ifndef PYDA_CORE_H
#define PYDA_CORE_H

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#define Py_BUILD_CORE
#include <internal/pycore_condvar.h>
#undef Py_BUILD_CORE

#ifdef PYDA_DYNAMORIO_CLIENT
#include <dr_api.h>
#include "hashtable.h"
#include "drvector.h"
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
};

struct pyda_process_s {
    int dirty_hooks;
    int refcount;

    pyda_thread *main_thread;
    PyObject *thread_init_hook;
    PyObject *syscall_pre_hook;
    PyObject *syscall_post_hook;

    PyObject *py_obj;

    pthread_cond_t thread_exit_cond;
    pthread_mutex_t refcount_mutex;

    int stdin_fd, stdout_fd, stderr_fd;

    void* entrypoint;

#ifdef PYDA_DYNAMORIO_CLIENT
    hashtable_t callbacks;
    drvector_t threads;
    drvector_t thread_run_untils; // vec of pcs
#endif

};

struct pyda_thread_s {
    unsigned long tid;

    pthread_cond_t resume_cond;
    pthread_cond_t break_cond;
    pthread_mutex_t mutex;

    int python_yielded, app_yielded;
    int python_blocked_on_io;

    pyda_process *proc;

    int rip_updated_in_python;
    int skip_next_hook; // Used when redirecting execution to same PC after a clean-call

    int python_exited; // Did this thread's python thread exit?
    int app_exited; // Did this thread's app thread exit?
    int errored; // Did some Pyda-misuse occur, or did the Python thread throw during a hook?

    int yield_count;
    uint64_t run_until;
    int dirty_run_until;

#ifdef PYDA_DYNAMORIO_CLIENT
    dr_mcontext_t cur_context;
#endif
};

pyda_process* pyda_mk_process();
pyda_thread* pyda_mk_thread(pyda_process*);

void pyda_capture_io(pyda_process *p, int use_pty, int pty_raw);

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
void pyda_set_syscall_pre_hook(pyda_process *p, PyObject *callback);
void pyda_set_syscall_post_hook(pyda_process *p, PyObject *callback);
pyda_hook* pyda_get_callback(pyda_process *p, void* addr);

void* pyda_get_run_until(pyda_thread *t);
void pyda_set_run_until(pyda_thread *t, void *pc);
void pyda_clear_run_until(pyda_thread *t);
int pyda_check_run_until(pyda_process *proc, void *test_pc);

// These can only be called from application threads
int pyda_flush_hooks();
void pyda_hook_cleancall(pyda_hook *cb);
int pyda_hook_syscall(int syscall_num, int is_pre);
void pyda_hook_rununtil_reached(void *pc);

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
