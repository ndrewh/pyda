
// We use this so that we have dr_set_tls_field
#define STATIC_DRMGR_ONLY

#include "dr_api.h"
#include "dr_tools.h"
#include "drmgr.h"
#include "Python.h"
#include "util.h"

#include <signal.h>

#include "pyda_core_py.h"
#include "pyda_core.h"
#include "pyda_threads.h"

extern void __ctype_init();

void python_init();
void python_main_thread(void*);
void python_aux_thread(void*);
void module_load_event(void *drcontext, const module_data_t *mod, bool loaded);
void thread_init_event(void *drcontext);
void thread_exit_event(void *drcontext);
static void thread_entrypoint_break();

void patch_python();

static dr_emit_flags_t event_analysis(void *drcontext, void *tag, instrlist_t *bb, char for_trace,
                  char translating, void **user_data);
static dr_emit_flags_t
event_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                 bool for_trace, bool translating, void *user_data);

static bool filter_syscall_event(void *drcontext, int sysnum);
static bool pre_syscall_event(void *drcontext, int sysnum);
static void post_syscall_event(void *drcontext, int sysnum);
static dr_signal_action_t signal_event(void *drcontext, dr_siginfo_t *siginfo);


extern int is_dynamorio_running;

pthread_cond_t python_thread_init1;
pthread_cond_t python_thread_init2;

int g_pyda_tls_idx;
int g_pyda_tls_is_python_thread_idx;
client_id_t pyda_client_id;

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("Pyda",
                       "https://github.com/ndrewh/pyda");
    
    pyda_client_id = id;

    /* Options */
    drmgr_init();

    is_dynamorio_running = 1;

    /* make it easy to tell, by looking at log file, which client executed */
    DEBUG_PRINTF("Client 'pyda' initializing\n");

    // Dynamically patch python
    patch_python();

    // dr_set_process_exit_behavior(DR_EXIT_MULTI_THREAD | DR_EXIT_SKIP_THREAD_EXIT);

    // python_init();
    // dr_create_client_thread(python_thread, NULL);
    drmgr_register_thread_init_event(thread_init_event);
    drmgr_register_thread_exit_event(thread_exit_event);

    drmgr_register_module_load_event(module_load_event);
    drmgr_register_bb_instrumentation_event(event_analysis,
                                            event_insert,
                                            NULL);
    
    drmgr_register_pre_syscall_event(pre_syscall_event);
    drmgr_register_post_syscall_event(post_syscall_event);
    dr_register_filter_syscall_event(filter_syscall_event);

    drmgr_register_signal_event(signal_event);

    pthread_cond_init(&python_thread_init1, 0);

    g_pyda_tls_idx = drmgr_register_tls_field();
    g_pyda_tls_is_python_thread_idx = drmgr_register_tls_field();
}

void module_load_event(void *drcontext, const module_data_t *mod, bool loaded) {
    DEBUG_PRINTF("module_load_event: %s\n", mod->full_path);
}

void thread_init_event(void *drcontext) {
    DEBUG_PRINTF("thread_init_event\n");

    // Make a thread structure
    static pyda_process *global_proc = NULL;
    pyda_thread *t;
    if (!global_proc) {
        global_proc = pyda_mk_process();

        pyda_prepare_io(global_proc);
        t = global_proc->main_thread;
    } else {
        t = pyda_mk_thread(global_proc);
    }

    DEBUG_PRINTF("thread_init_event %p thread %d\n", (void*)t, dr_get_thread_id(drcontext));

    // WARN: This must use drcontext passed in.
    drmgr_set_tls_field(drcontext, g_pyda_tls_idx, (void*)t);
    drmgr_set_tls_field(drcontext, g_pyda_tls_is_python_thread_idx, (void*)0);

    // some init that python requires(?)
    __ctype_init();

    if (global_proc->main_thread->python_exited) {
        t->errored = 1;
    }

    // Every thread has its own corresponding python thread
    if (t == global_proc->main_thread) {
        dr_create_client_thread(python_main_thread, t);
    } else {
        dr_create_client_thread(python_aux_thread, t);
    }

    // Store the first pc, we will intrument it to call break
    if (t == global_proc->main_thread) {
        module_data_t *main_mod = dr_get_main_module();
        t->proc->entrypoint = (void*)main_mod->entry_point;
    } else {
        dr_mcontext_t mc;
        mc.size = sizeof(mc);
        mc.flags = DR_MC_ALL;
        dr_get_mcontext(drcontext, &mc);

        DEBUG_PRINTF("aux thread initial break\n");
        pyda_initial_break(t);
        DEBUG_PRINTF("aux thread initial break end\n");
    }
    DEBUG_PRINTF("thread_init_event end: %p\n", (void*)t);
}

void thread_exit_event(void *drcontext) {
    pyda_thread *t = drmgr_get_tls_field(drcontext, g_pyda_tls_idx);

    DEBUG_PRINTF("thread_exit_event: %p thread id %d\n", t, dr_get_thread_id(drcontext));
    t->app_exited = 1;

    pyda_break_noblock(t);
}

void python_init() {
    static bool is_init = false;
    if (is_init) return;
    is_init = true;

    DEBUG_PRINTF("python_init\n");
    // sleep(5);
    wchar_t *program = Py_DecodeLocale("program_name", NULL);
    if (program == NULL) {
        DEBUG_PRINTF("Fatal error: cannot decode argv[0]\n");
        exit(1);
    }

    /* Add the pyda_core module */
    if (PyImport_AppendInittab("pyda_core", PyInit_pyda_core) == -1) {
        fprintf(stderr, "Error: could not extend in-built modules table\n");
        exit(1);
    }

    Py_SetProgramName(program);  /* optional but recommended */
    PyConfig config;
    PyConfig_InitPythonConfig(&config);

    int argc;
    const char **argv;
    dr_get_option_array(pyda_client_id, &argc, &argv);

    PyConfig_SetBytesArgv(&config, argc, (char * const *)argv);
    config.parse_argv = 0;

    // Output is much happier if we don't buffer.
    config.buffered_stdio = 0;

    Py_InitializeFromConfig(&config);

    DEBUG_PRINTF("python_init2\n");

#ifndef NDEBUG
    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();

    // Check that the python interpreter is functional
    PyRun_SimpleString("from time import time,ctime\n"
                       "print('You are running Pyda v" PYDA_VERSION ".');\n"
    );
    DEBUG_PRINTF("python_init3\n");
    PyGILState_Release(gstate);
#endif
}

static dr_emit_flags_t
event_analysis(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
                  bool translating, void **user_data)
{
    return DR_EMIT_DEFAULT;
}
static dr_emit_flags_t
event_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                 bool for_trace, bool translating, void *user_data)
{
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    pyda_hook *callback;

    // XXX: I don't think this is safe, since the thread that updates
    // the code cache may not be the executing thread.
    if (instr_get_app_pc(instr) == t->proc->entrypoint) {
        DEBUG_PRINTF("** Found PC\n");
        dr_insert_clean_call(drcontext, bb, instrlist_first_app(bb), (void *)thread_entrypoint_break,
                         false /* save fpstate */, 0);
    } else if ((callback = pyda_get_callback(t->proc, instr_get_app_pc(instr)))) {
        DEBUG_PRINTF("installing hook at %p\n", instr_get_app_pc(instr));
        dr_insert_clean_call(drcontext, bb, instr, (void *)pyda_hook_cleancall,
                         true /* save fpstate */, 1, OPND_CREATE_INTPTR(callback));
    } else if (pyda_check_run_until(t->proc, instr_get_app_pc(instr))) {
        DEBUG_PRINTF("installing run_until hook at %p\n", instr_get_app_pc(instr));
        dr_insert_clean_call(drcontext, bb, instr, (void *)pyda_hook_rununtil_reached,
                         true /* save fpstate */, 1, OPND_CREATE_INTPTR(instr_get_app_pc(instr)));
    }
    return DR_EMIT_DEFAULT;
}

static bool filter_syscall_event(void *drcontext, int sysnum) {
    // TODO: Check the list of desired syscalls
    return true;
}

static bool pre_syscall_event(void *drcontext, int sysnum) {
    if (drcontext != dr_get_current_drcontext()) {
        DEBUG_PRINTF("pre_syscall_event: drcontext mismatch\n");
        return true;
    }
    return pyda_hook_syscall(sysnum, 1);
}

static void post_syscall_event(void *drcontext, int sysnum) {
    if (drcontext != dr_get_current_drcontext()) {
        DEBUG_PRINTF("post_syscall_event: drcontext mismatch\n");
    }
    pyda_hook_syscall(sysnum, 0);
}

static dr_signal_action_t signal_event(void *drcontext, dr_siginfo_t *siginfo) {
    pyda_thread *t = drmgr_get_tls_field(drcontext, g_pyda_tls_idx);

    int sig = siginfo->sig;

    // We only care about signals that indicate crashes. We only care if the python thread
    // is still running (We need to have someone to raise the exception to!)
    // Perhaps unexpectedly, we also only care if the process has not blocked the signal.
    // This prevents us from handling signals when the application has blocked them (e.g.,
    // because it is holding the GIL. We will still handle them before the app gets them.)
    if ((sig == SIGSEGV || sig == SIGBUS || sig == SIGILL) && !t->python_exited && !siginfo->blocked) {
        memcpy(&t->cur_context, siginfo->mcontext, sizeof(dr_mcontext_t));
        t->signal = sig;

        // Clear any previous run_until hooks: they are now invalid
        // since we are throwing.
        if (t->run_until)
            pyda_clear_run_until(t);
        
        // Raise an exception in Python +
        // Wait for Python to yield back to us
        pyda_break(t);

        // Flushing is actually allowed in signal event handlers.
        // This updates run_until handlers, updated hooks, etc.
        pyda_flush_hooks();

        // Copy the state back to the siginfo
        memcpy(siginfo->mcontext, &t->cur_context, sizeof(dr_mcontext_t));

        t->signal = 0;

        return DR_SIGNAL_REDIRECT;
    }

    return DR_SIGNAL_DELIVER;
}

static void thread_entrypoint_break() {
    DEBUG_PRINTF("entrypoint (break)\n");

    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    DEBUG_PRINTF("[PYDA] New thread %ld\n", t->tid);

    pyda_initial_break(t);
    if (pyda_flush_hooks()) {
        DEBUG_PRINTF("entrypoint: flush hooks\n");

        // We may have flushed the current fragment, so we have to call
        // dr_redirect_execution instead of returning.
        dr_mcontext_t mc;
        mc.size = sizeof(mc);
        mc.flags = DR_MC_ALL;
        dr_get_mcontext(dr_get_current_drcontext(), &mc);
        mc.pc = t->proc->entrypoint;
        t->proc->entrypoint = 0; // avoid breaking a second time
        dr_flush_region((void*)mc.pc, 1);
        dr_redirect_execution(&mc);
    }
    DEBUG_PRINTF("entrypoint (break end)\n");
}

void drmgr_thread_init_event(void*);

static void* python_thread_init(pyda_thread *t) {
    __ctype_init();

    void *drcontext = dr_get_current_drcontext();
    void *tls = dr_thread_alloc(drcontext, sizeof(void*) * 130);
    memset(tls, 0, sizeof(void*) * 130);
    dr_set_tls_field(drcontext, (void *)tls);

    dr_client_thread_set_suspendable(false);
    pyda_thread_setspecific(g_pyda_tls_idx, (void*)t);
    pyda_thread_setspecific(g_pyda_tls_is_python_thread_idx, (void*)1);
    return tls;
}

void python_main_thread(void *arg) {
    pyda_thread *t = arg;
    void *drcontext = dr_get_current_drcontext();
    void *tls = python_thread_init(t);

    python_init();

    if (!PyGILState_Check()) {
        fprintf(stderr, "[Pyda] Error: GIL expected\n");
        dr_abort();
    }

    DEBUG_PRINTF("Running script...\n");

    const char *script_name = getenv("PYDA_SCRIPT");
    if (!script_name) {
        fprintf(stderr, "[Pyda] Error: PYDA_SCRIPT not set\n");
    }

    FILE *f = fopen(script_name, "r");
    if (!f) {
        fprintf(stderr, "[Pyda] Error: could not open %s\n", script_name);
        goto python_exit;
    }

    // The thread will be holding the lock until
    // it reaches the "initial" breakpoint
    pthread_mutex_lock(&t->mutex);
    pthread_mutex_unlock(&t->mutex);

    if (PyRun_SimpleFile(f, script_name) == -1) {
        // python exception
    }

    fclose(f);

python_exit:
    DEBUG_PRINTF("Script exited...\n");
    t->python_exited = 1;
    t->errored = 1;

    // dr_client_thread_set_suspendable(true);
    DEBUG_PRINTF("After script exit, GIL status %d\n", PyGILState_Check());
    PyEval_SaveThread(); // release GIL

    if (!t->app_exited) {
        if (t->yield_count == 0)
            dr_fprintf(STDERR, "[Pyda] ERROR: Did you forget to call p.run()?\n");
        pyda_yield(t); // unblock (note: blocking)
        DEBUG_PRINTF("Implicit pyda_yield finished\n");
    }

    // This call will block until the main thread is the last.
    DEBUG_PRINTF("python_main_thread destroy\n");
    pyda_thread_destroy_last(t);
    DEBUG_PRINTF("python_main_thread destroy done\n");

    DEBUG_PRINTF("Py_FinalizeEx in thread %d\n", dr_get_thread_id(drcontext));
    PyGILState_STATE gstate = PyGILState_Ensure();
    if (Py_FinalizeEx() < 0) {
        DEBUG_PRINTF("WARN: Python finalization failed\n");
    }
    DEBUG_PRINTF("Py_FinalizeEx done\n");

    dr_thread_free(drcontext, tls, sizeof(void*) * 130);
    DEBUG_PRINTF("python_main_thread return\n");
}

void python_aux_thread(void *arg) {
    pyda_thread *t = arg;
    void *drcontext = dr_get_current_drcontext();
    void *tls = python_thread_init(t);

    DEBUG_PRINTF("python_aux_thread id %d\n", dr_get_thread_id(drcontext));

    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();

    DEBUG_PRINTF("python_aux_thread id %d locked\n", dr_get_thread_id(drcontext));

    // We just call the thread init hook, if one exists
    if (t->proc->thread_init_hook && !t->errored) {
        DEBUG_PRINTF("Calling thread_init_hook\n");
        PyObject *result = PyObject_CallFunctionObjArgs(t->proc->thread_init_hook, t->proc->py_obj, NULL);
        if (result == NULL) {
            PyErr_Print();
            dr_fprintf(STDERR, "[Pyda] ERROR: Thread entry hook failed. Continuing.\n");
            // dr_abort();
        }
    }

    PyGILState_Release(gstate);

    dr_client_thread_set_suspendable(true);
    DEBUG_PRINTF("python_aux_thread 4\n");

    t->python_exited = 1;

    if (!t->app_exited) {
        pyda_yield(t);
        DEBUG_PRINTF("Implicit pyda_yield finished\n");
    }

    pyda_thread_destroy(t);

    DEBUG_PRINTF("python_aux_thread 5\n");
    dr_thread_free(drcontext, tls, sizeof(void*) * 130);
    DEBUG_PRINTF("python_aux_thread 6\n");
}