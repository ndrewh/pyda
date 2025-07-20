
// We use this so that we have dr_set_tls_field
#define STATIC_DRMGR_ONLY

#include "dr_api.h"
#include "dr_tools.h"
#include "drmgr.h"
#include "drreg.h"
#include "Python.h"
#include "pyda_util.h"

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
static void fork_event(void *drcontext);
static void event_attach_post(void);


extern int is_dynamorio_running;
extern int pyda_attach_mode;

int is_python_init;

int g_pyda_tls_idx;
int g_pyda_tls_is_python_thread_idx;
client_id_t pyda_client_id;

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("Pyda",
                       "https://github.com/ndrewh/pyda");

    pyda_client_id = id;

    drreg_options_t ops = { sizeof(ops), 0 /*no slots needed*/, true /* conservative */};
    if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS) {
        dr_fprintf(STDERR, "pyda: error in drmgr or drreg initialization\n");
        dr_abort();
    }


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
    dr_register_post_attach_event(event_attach_post);

    drmgr_register_signal_event(signal_event);
    dr_register_fork_init_event(fork_event);
    dr_request_synchronized_exit();

    g_pyda_tls_idx = drmgr_register_tls_field();
    g_pyda_tls_is_python_thread_idx = drmgr_register_tls_field();
}

void module_load_event(void *drcontext, const module_data_t *mod, bool loaded) {
    DEBUG_PRINTF("module_load_event: %s\n", mod->full_path);
    
    if (loaded) {
        pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
        pyda_hook_module_load(mod->full_path);
    }
}

void thread_init_event(void *drcontext) {
    DEBUG_PRINTF("thread_init_event\n");
    module_data_t *main_mod = dr_get_main_module();

    if (!main_mod) {
        DEBUG_PRINTF("main_mod is NULL\n");
        return;
    }

    // Make a thread structure
    static pyda_process *global_proc = NULL;
    pyda_thread *t;
    if (!global_proc) {
        global_proc = pyda_mk_process();

        pyda_prepare_io(global_proc);
        t = global_proc->main_thread;
        if (!getenv("PYTHONPATH")) {
            parse_proc_environ();
        }
    } else {
        t = pyda_mk_thread(global_proc);
    }

    DEBUG_PRINTF("thread_init_event %p thread %d\n", (void*)t, dr_get_thread_id(drcontext));

    // WARN: This must use drcontext passed in.
    drmgr_set_tls_field(drcontext, g_pyda_tls_idx, (void*)t);
    drmgr_set_tls_field(drcontext, g_pyda_tls_is_python_thread_idx, (void*)0);

    // some init that python requires(?)
#ifdef LINUX
    __ctype_init();
#endif

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
        t->proc->entrypoint = (void*)main_mod->entry_point;

        if (!getenv("PYDA_NO_ATTACH")) {
            pyda_attach_mode = 1;
            // In attach mode, the entrypoint will never be reached,
            // so we release the lock now
            DEBUG_PRINTF("PYDA_NO_ATTACH is not set, assuming attach mode\n")
            pthread_mutex_unlock(&t->mutex);
        }
    } else {
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
    /* dr_fprintf(STDERR, "pyda_break\n"); */
}

static const char *script_name;

static void get_python_args(int *o_argc, const char ***o_argv) {
    int argc;
    const char **argv;
    const char **new_argv;

    dr_get_option_array(pyda_client_id, &argc, &argv);

    if (argc >= 3 && strcmp(argv[1], "-script") == 0) {
        script_name = strdup(argv[2]);
        argc -= 2;

        // Copy to new memory
        new_argv = dr_global_alloc(sizeof(const char*) * (argc + 1));
        for (int i=0; i<argc; i++) {
            new_argv[i] = strdup(argv[i+2]);
        }

        new_argv[argc] = NULL;
        new_argv[0] = strdup(argv[0]);

        // Shift out the two "-script X" arguments
        DEBUG_PRINTF("Using script from command line: %s\n", script_name);
    } else {
        script_name = getenv("PYDA_SCRIPT");

        // Copy to new memory
        new_argv = dr_global_alloc(sizeof(const char*) * (argc + 1));
        for (int i=0; i<argc; i++) {
            new_argv[i] = strdup(argv[i]);
        }
        new_argv[argc] = NULL;
    }

    *o_argc = argc;
    *o_argv = new_argv;
}

void python_init() {
    static bool is_init = false;
    if (is_init) return;
    is_init = true;

    DEBUG_PRINTF("python_init\n");
    // sleep(10);
    /* Add the pyda_core module */
    if (PyImport_AppendInittab("pyda_core", PyInit_pyda_core) == -1) {
        fprintf(stderr, "Error: could not extend in-built modules table\n");
        exit(1);
    }

#ifndef MACOS
    wchar_t *program = Py_DecodeLocale("python3", NULL);
    if (program == NULL) {
        DEBUG_PRINTF("Fatal error: cannot decode argv[0]\n");
        exit(1);
    }

    Py_SetProgramName(program);
#endif // macOS uses PYTHONEXECUTABLE

    PyConfig config;
    PyConfig_InitPythonConfig(&config);

    int argc;
    const char **argv;
    get_python_args(&argc, &argv);
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
    //
#if defined(X86)
    dr_cleancall_save_t save_flags = DR_CLEANCALL_READS_APP_CONTEXT | DR_CLEANCALL_WRITES_APP_CONTEXT | DR_CLEANCALL_SAVE_FLOAT;
#elif defined(AARCH64)
    dr_cleancall_save_t save_flags = DR_CLEANCALL_READS_APP_CONTEXT | DR_CLEANCALL_WRITES_APP_CONTEXT;
#else
    #error "Unsupported arch"
#endif

    if (instr_is_app(instr)) {
        if (instr_get_app_pc(instr) == t->proc->entrypoint) {
            DEBUG_PRINTF("** Found Entrypoint\n");
            dr_insert_clean_call_ex(drcontext, bb, instr, (void *)thread_entrypoint_break,
                            save_flags, 0);
        } else if ((callback = pyda_get_callback(t->proc, instr_get_app_pc(instr)))) {
            DEBUG_PRINTF("installing hook at %p\n", instr_get_app_pc(instr));
            if (callback->callback_type == 0) {
                dr_insert_clean_call_ex(drcontext, bb, instr, (void *)pyda_hook_cleancall,
                                save_flags /* save flags */, 1, OPND_CREATE_INTPTR(callback));
            } else if (callback->callback_type == 1) {
                pyda_handle_advanced_hook(bb, instr, callback);
            }
        } else if (pyda_check_run_until(t->proc, instr_get_app_pc(instr))) {
            DEBUG_PRINTF("installing run_until hook at %p\n", instr_get_app_pc(instr));
            dr_insert_clean_call_ex(drcontext, bb, instr, (void *)pyda_hook_rununtil_reached,
                            save_flags /* save flags */, 1, OPND_CREATE_INTPTR(instr_get_app_pc(instr)));
        }
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

    DEBUG_PRINTF("signal_event tid=%d: %d\n", t->tid, siginfo->sig);

    int sig = siginfo->sig;

    // We only care about signals that indicate crashes. We only care if the python thread
    // is still running (We need to have someone to raise the exception to!)
    // Perhaps unexpectedly, we also only care if the process has not blocked the signal.
    // This prevents us from handling signals before the application is ready for them (e.g.,
    // because it is holding the GIL. We will still handle them before the app gets them,
    // since dynamorio will call the handler a second time.)
    if ((sig == SIGSEGV || sig == SIGBUS || sig == SIGILL || sig == SIGABRT) && !siginfo->blocked) {
        if (!t->python_exited) {
            memcpy(&t->cur_context, siginfo->mcontext, sizeof(dr_mcontext_t));
            t->signal = sig;

            // Clear any previous run_until hooks: they are now invalid
            // since we are throwing.
            if (t->run_until)
                pyda_clear_run_until(t);

            // Raise an exception in Python +
            // Wait for Python to yield back to us
            pyda_break(t);

            if (!t->python_exited) {
                // Flushing is actually allowed in signal event handlers.
                // This updates run_until handlers, updated hooks, etc.
                pyda_flush_hooks();

                // Copy the state back to the siginfo
                memcpy(siginfo->mcontext, &t->cur_context, sizeof(dr_mcontext_t));

                t->signal = 0;

                return DR_SIGNAL_REDIRECT;
            }
            //
            // If Python exited (e.g. by not catching the FatalSignalError), we allow this
            // to fall through and deliver the signal anyway
            //
            dr_fprintf(STDERR, "[Pyda] Script did not handle FatalSignalError. Delivering signal %d.\n", sig);
        } else {
            dr_fprintf(STDERR, "[Pyda] ERROR: Signal %d received after Python exited/died. Add p.run() to receive the signal as an exception.\n", sig);
        }
    }

    return DR_SIGNAL_DELIVER;
}
static void fork_event(void *drcontext) {
    // This is called on the NEW fork, which doesn't have any parallel Python threads anymore.
    // TODO: How do we make sure that important locks aren't held at fork time when we have multiple threads?
    pyda_thread *t = drmgr_get_tls_field(drcontext, g_pyda_tls_idx);
    DEBUG_PRINTF("[Pyda] fork_init\n");

    pyda_process *p = t->proc;

    // Flush deleted hooks
    drvector_lock(&p->threads);
    for (int i=0; i<p->threads.entries; i++) {
        dr_flush_file(STDERR);
        if (p->threads.array[i] != t) pyda_thread_destroy(p->threads.array[i]);
    }
    p->threads.entries = 1;
    p->threads.array[0] = t;
    drvector_unlock(&p->threads);

    // For now, we just mark the current thread as exited, which just means we won't
    // try to yield to it in signal handlers or if we reach the last run_until hook.
    //
    // In the future, we could setup a new parallel Python thread that enters some
    // "fork handler" as the entrypoint or whatever

    t->python_exited = 1;
    p->main_thread = t;
}

static void event_attach_post() {
    if (!pyda_attach_mode) {
        dr_fprintf(STDERR, "Internal error: PYDA_NO_ATTACH is set but attach callback used\n");
        dr_abort();
        return;
    }

    DEBUG_PRINTF("event_attach_post on tid %d\n", dr_get_thread_id(dr_get_current_drcontext()));

    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    DEBUG_PRINTF("[PYDA] Main thread (attached) is %ld\n", t->tid);

    if (t->proc->main_thread != t) {
        dr_fprintf(STDERR, "[Pyda] ERROR: Dynamorio is not running on the main thread. This is probably a bug.\n");
        dr_abort();
    }

    pthread_mutex_lock(&t->mutex); // we intentionally released the mutex based on `pyda_attach_mode`
    pyda_initial_break(t); // wait for the script to call p.run()

    // XXX: Not clear if this is legal to call here. If it is, we should note that we don't
    // have to redirect execution, because we aren't actually in translated code yet!
    /* pyda_flush_hooks(); */

    DEBUG_PRINTF("entrypoint end (attach)\n");
}

static void thread_entrypoint_break() {
    DEBUG_PRINTF("entrypoint (break)\n");

    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    DEBUG_PRINTF("[PYDA] Main thread at entrypiont %ld\n", t->tid);

    pyda_initial_break(t);
    DEBUG_PRINTF("entrypoint break end\n");
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

void python_main_thread(void *arg) {
    pyda_thread *t = arg;
    void *drcontext = dr_get_current_drcontext();
    void *tls = python_thread_init(t);

    python_init();

    if (!PyGILState_Check()) {
        dr_fprintf(STDERR, "[Pyda] Error: GIL expected\n");
        dr_abort();
    }

    DEBUG_PRINTF("Running script...\n");
    /* sleep(10); */

    if (!script_name) {
        dr_fprintf(STDERR, "[Pyda] Error: Script not specified\n");
        goto python_exit;
    }

    FILE *f = fopen(script_name, "r");
    if (!f) {
        dr_fprintf(STDERR, "[Pyda] Error: could not open %s\n", script_name);
        goto python_exit;
    }

    // The thread will be holding the lock until
    // it reaches the "initial" breakpoint
    pthread_mutex_lock(&t->mutex);
    pthread_mutex_unlock(&t->mutex);

    // This is a good place to put a sleep to attach GDB
    // if testing out the attach mode
    // sleep(15);

    if (PyRun_SimpleFile(f, script_name) == -1) {
        // python exception
        dr_fprintf(STDERR, "[Pyda] Script raised exception, see above.\n");
    }

    fclose(f);

python_exit:
    DEBUG_PRINTF("Script exited...\n");
    t->python_exited = 1;
    t->errored = 1;

    DEBUG_PRINTF("After script exit, GIL status %d\n", PyGILState_Check());

    Py_BEGIN_ALLOW_THREADS;

    if (!t->app_exited) {
        if (!t->signal)
            dr_fprintf(STDERR, "[Pyda] ERROR: Did you forget to call p.run()?\n");

        DEBUG_PRINTF("Implicit pyda_yield start\n");
        pyda_yield(t); // unblock (note: blocking)
        DEBUG_PRINTF("Implicit pyda_yield finished\n");
    }

    // This call will block until the main thread is the last.
    DEBUG_PRINTF("python_main_thread destroy\n");
    pyda_thread_destroy_last(t);
    DEBUG_PRINTF("python_main_thread destroy done\n");

    DEBUG_PRINTF("Py_FinalizeEx in thread %d\n", dr_get_thread_id(drcontext));

    Py_END_ALLOW_THREADS;

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

    // Wait for the main script to reach the first yield (so there is time to set thread_init_hook in the attach case)
    pthread_mutex_lock(&t->proc->main_thread->mutex);
    while (!t->proc->main_thread->yield_count)
        pthread_cond_wait(&t->proc->main_thread->resume_cond, &t->proc->main_thread->mutex);
    pthread_mutex_unlock(&t->proc->main_thread->mutex);

    DEBUG_PRINTF("python_aux_thread enter id %d\n", dr_get_thread_id(drcontext));

    // Acquire the GIL so this thread can call the thread entrypoint
    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();

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

    // dr_client_thread_set_suspendable(true);

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
