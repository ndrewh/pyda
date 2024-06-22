
// We use this so that we have dr_set_tls_field
#define STATIC_DRMGR_ONLY

#include "dr_api.h"
#include "dr_tools.h"
#include "drmgr.h"
#include "Python.h"
#include "util.h"

#include "pyda_core_py.h"
#include "pyda_core.h"
#include "pyda_threads.h"

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

extern int is_dynamorio_running;

pthread_cond_t python_thread_init1;
pthread_cond_t python_thread_init2;
pthread_mutex_t python_thread_init1_mutex;

int g_pyda_tls_idx;
client_id_t pyda_client_id;

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Python Hook Client",
                       "https://github.com/ndrewh");
    
    pyda_client_id = id;

    /* Options */
    drmgr_init();

    is_dynamorio_running = 1;

    /* make it easy to tell, by looking at log file, which client executed */
    DEBUG_PRINTF("Client 'python_hook' initializing\n");

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

    pthread_cond_init(&python_thread_init1, 0);
    pthread_mutex_init(&python_thread_init1_mutex, 0);

    g_pyda_tls_idx = drmgr_register_tls_field();
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
        t = global_proc->main_thread;
    } else {
        t = pyda_mk_thread(global_proc);
    }

    drmgr_set_tls_field(drcontext, g_pyda_tls_idx, (void*)t);

    // Every thread has its own corresponding python thread
    if (t == global_proc->main_thread) {
        python_init();
        dr_create_client_thread(python_main_thread, t);
    } else {
        dr_create_client_thread(python_aux_thread, t);
    }

    // Store the first pc, we will intrument it to call break
    if (t == global_proc->main_thread) {
        module_data_t *main_mod = dr_get_main_module();
        t->start_pc = (void*)main_mod->entry_point;
    } else {
        dr_mcontext_t mc;
        mc.size = sizeof(mc);
        mc.flags = DR_MC_ALL;
        dr_get_mcontext(drcontext, &mc);
        t->start_pc = (void*)mc.rip;
        DEBUG_PRINTF("start_pc: %p\n", t->start_pc);
        dr_flush_region(t->start_pc, 1);
    }
    DEBUG_PRINTF("thread_init_event: %p\n", t->start_pc);
}

void thread_exit_event(void *drcontext) {
    DEBUG_PRINTF("thread_exit_event\n"); 
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    DEBUG_PRINTF("thread_exit_event: %p\n", t);
    dr_abort();

    pyda_break(t);
    DEBUG_PRINTF("broke end\n", t);
    // TODO: exit event
    pyda_thread_destroy(t);
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
    Py_InitializeFromConfig(&config);

    pthread_mutex_lock(&python_thread_init1_mutex);
    DEBUG_PRINTF("python_init2\n");

    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();

    // Check that the python interpreter is functional
    PyRun_SimpleString("from time import time,ctime\n"
                       "print('You are running Pyda v" PYDA_VERSION ".');\n"
    );
    DEBUG_PRINTF("python_init3\n");
    // PyGILState_Release(gstate);
    pthread_mutex_unlock(&python_thread_init1_mutex);
    // temporary
    PyThreadState *_save;
    Py_UNBLOCK_THREADS
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
    if (instr_get_app_pc(instr) == t->start_pc) {
        DEBUG_PRINTF("** Found PC\n");
        dr_insert_clean_call(drcontext, bb, instrlist_first_app(bb), (void *)thread_entrypoint_break,
                         false /* save fpstate */, 0);
    } else if ((callback = pyda_get_callback(t->proc, instr_get_app_pc(instr)))) {
        DEBUG_PRINTF("installing hook at %p\n", instr_get_app_pc(instr));
        dr_insert_clean_call(drcontext, bb, instr, (void *)pyda_hook_cleancall,
                         true /* save fpstate */, 1, OPND_CREATE_INTPTR(callback));
    }
    return DR_EMIT_DEFAULT;
}

static void thread_entrypoint_break() {
    DEBUG_PRINTF("entrypoint (break)\n");

    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    fprintf(stderr, "[PYDA] New thread %ld\n", t->tid);

    pyda_initial_break(t);
    if (pyda_flush_hooks()) {
        DEBUG_PRINTF("dr_flush_hooks\n");

        // We may have flushed the current fragment, so we have to call
        // dr_redirect_execution instead of returning.
        dr_mcontext_t mc;
        mc.size = sizeof(mc);
        mc.flags = DR_MC_ALL;
        dr_get_mcontext(dr_get_current_drcontext(), &mc);
        mc.pc = t->start_pc;

        t->start_pc = 0; // avoid breaking a second time

        dr_redirect_execution(&mc);
    }
    DEBUG_PRINTF("entrypoint (break end)\n");
}

void __ctype_init();
void drmgr_thread_init_event(void*);

static void* python_thread_init(pyda_thread *t) {
    __ctype_init();

    void *drcontext = dr_get_current_drcontext();
    void *tls = dr_thread_alloc(drcontext, sizeof(void*) * 130);
    memset(tls, 0, sizeof(void*) * 130);
    dr_set_tls_field(drcontext, (void *)tls);

    dr_client_thread_set_suspendable(false);
    pyda_thread_setspecific(g_pyda_tls_idx, (void*)t);
    return tls;
}

void python_main_thread(void *arg) {
    pyda_thread *t = arg;
    void *drcontext = dr_get_current_drcontext();
    void *tls = python_thread_init(t);

    pthread_mutex_lock(&python_thread_init1_mutex);
    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();

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

    if (PyRun_SimpleFile(f, script_name) == -1) {
        // python exception
    }

    fclose(f);

python_exit:

    DEBUG_PRINTF("Script exited...\n");

    PyGILState_Release(gstate);
    pthread_mutex_unlock(&python_thread_init1_mutex);

    dr_client_thread_set_suspendable(true);
    pyda_yield(t); // unblock

    dr_thread_free(drcontext, tls, sizeof(void*) * 130);
    DEBUG_PRINTF("Calling dr_exit\n");

    // pyda_thread_destroy(t);
    drmgr_exit();
}

void python_aux_thread(void *arg) {
    pyda_thread *t = arg;
    void *drcontext = dr_get_current_drcontext();
    void *tls = python_thread_init(t);

    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();

    // We just call the thread init hook, if one exists
    if (t->proc->thread_init_hook) {
        PyObject *result = PyObject_CallFunctionObjArgs(t->proc->thread_init_hook, t->proc->main_thread->py_obj, NULL);
    }

    PyGILState_Release(gstate);

    dr_client_thread_set_suspendable(true);
    pyda_yield(t); // unblock

    dr_thread_free(drcontext, tls, sizeof(void*) * 130);
}