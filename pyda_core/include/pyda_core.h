#ifndef PYDA_CORE_H
#define PYDA_CORE_H

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#define Py_BUILD_CORE
#include <internal/pycore_condvar.h>
#undef Py_BUILD_CORE

#include <dr_api.h>
#include "hashtable.h"
#include "drvector.h"
#include "pyda_compiler.h"

#define SCRATCH_SLOTS 16


extern int is_dynamorio_running;
typedef struct pyda_hook_s pyda_hook;
typedef struct pyda_thread_s pyda_thread;
typedef struct pyda_process_s pyda_process;

// Since we have multiple threads running, we need to keep track of
// which one is holding the GIL.

struct pyda_hook_s {
    PyObject *py_func;
    unsigned callback_type:2;  // 0 = normal hook, 1 = advanced instrumentation
    unsigned deleted:1; // This is set when the hook has been fully flushed from code cache.
    void *addr;
};

struct pyda_process_s {
    int refcount;

    pyda_thread *main_thread;
    PyObject *thread_init_hook;
    PyObject *syscall_pre_hook;
    PyObject *syscall_post_hook;
    PyObject *module_load_hook;

    PyObject *py_obj;

    pthread_cond_t thread_exit_cond;
    pthread_mutex_t refcount_mutex;

    int stdin_fd, stdout_fd, stderr_fd;

    void* entrypoint;

#ifdef PYDA_DYNAMORIO_CLIENT
    hashtable_t callbacks;
    drvector_t threads;
    drvector_t thread_run_untils; // vec of pcs
    int flush_count;
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

    int signal; // 0 if no signal, otherwise the signal number

#ifdef PYDA_DYNAMORIO_CLIENT
    dr_mcontext_t cur_context;
    drvector_t context_stack;

    // thread-local list of hooks to be flushed; guarantees that changes go into
    // effect when expected: e.g., when returning from a hook
    drvector_t hook_update_queue;

    // records the last seen proc->flush_count so that we don't return into a stale fragment
    int flush_ts; 
#endif

    ExprBuilder *expr_builder;

    uint64_t scratch_region[SCRATCH_SLOTS];
};

struct pyda_bt_entry {
    char modname[128];
    uint64_t offset;
    char sym_name[512];
    uint64_t ip;
    uint64_t sp;
};


pyda_process* pyda_mk_process();
pyda_thread* pyda_mk_thread(pyda_process*);

void pyda_capture_io(pyda_process *p, int use_pty, int pty_raw);
void pyda_prepare_io(pyda_process *p);

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

// NOTE: GIL should be held for these
void pyda_add_hook(pyda_process *p, uint64_t addr, PyObject *callback, int callback_type, int needs_flush);
void pyda_remove_hook(pyda_process *p, uint64_t addr);
void pyda_set_thread_init_hook(pyda_process *p, PyObject *callback);
void pyda_set_syscall_pre_hook(pyda_process *p, PyObject *callback);
void pyda_set_syscall_post_hook(pyda_process *p, PyObject *callback);
void pyda_set_module_load_hook(pyda_process *p, PyObject *callback);

pyda_hook* pyda_get_callback(pyda_process *p, void* addr);

void* pyda_get_run_until(pyda_thread *t);
void pyda_set_run_until(pyda_thread *t, void *pc);
void pyda_clear_run_until(pyda_thread *t);
int pyda_check_run_until(pyda_process *proc, void *test_pc);

// These can only be called from application threads
int pyda_flush_hooks();
void pyda_hook_cleancall(pyda_hook *cb);
int pyda_hook_syscall(int syscall_num, int is_pre);
void pyda_hook_module_load(const char *module_path);
void pyda_hook_rununtil_reached(void *pc);

int pyda_push_context(pyda_thread *t);
int pyda_pop_context(pyda_thread *t);

int pyda_get_backtrace (pyda_thread *t, drvector_t *res);

void pyda_handle_advanced_hook(instrlist_t *bb, instr_t *instr, pyda_hook *callback);

typedef struct {
    PyObject_HEAD
    struct ExprBuilder *builder;
} PydaExprBuilder;


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
