
#include "pyda_core.h"
#include "pyda_threads.h"
#ifdef PYDA_DYNAMORIO_CLIENT

#include "dr_api.h"
#include "dr_tools.h"
#include "drmgr.h"
#include "privload.h"

static redirect_import_t python_redirect_imports[] = {
    { "pthread_key_create", (app_pc)pyda_thread_key_create },
    { "pthread_key_delete", (app_pc)pyda_thread_key_delete },
    { "pthread_getspecific", (app_pc)pyda_thread_getspecific },
    { "pthread_setspecific", (app_pc)pyda_thread_setspecific },
    { "pthread_cond_init", (app_pc)pyda_cond_init },
    { "pthread_cond_timedwait", (app_pc)pyda_cond_timedwait },
    { "pthread_cond_signal", (app_pc)pyda_cond_signal },
    { "pthread_mutex_init", (app_pc)pyda_mutex_init },
    { "pthread_self", (app_pc)pyda_thread_self },
    { "pthread_create", (app_pc)pyda_thread_create },
    { "pthread_detach", (app_pc)pyda_thread_detach },
    { "dlopen", (app_pc)pyda_dlopen },
    { "dlsym", (app_pc)pyda_dlsym },
};

#define NUM_NEW_IMPORTS (sizeof(python_redirect_imports) / sizeof(redirect_import_t))
void patch_python() {
    // // module_data_t *mod = dr_lookup_module_by_name("libpython3.10.so.1.0");
    // // iterate over modules

    // if (!mod) {
    //     dr_fprintf(STDERR, "Could not find libpython3.10.so.1.0\n");
    //     return;
    // }

    // // Find beginning of got
    // for (int i=0; i < mod->num_segments; i++) {
    //     module_segment_data_t *seg = &mod->segments[0];
    //     if ((seg->prot & DR_MEMPROT_READ | DR_MEMPROT_WRITE) == DR_MEMPROT_READ | DR_MEMPROT_WRITE) {
    //         dr_fprintf(STDERR, "Found writable segment at %p\n", seg->start);
    //     }
    // }

    client_redirect_imports = python_redirect_imports;
    client_redirect_imports_count = NUM_NEW_IMPORTS;
    privmod_t *mod = privload_lookup_by_pc_takelock((app_pc)&PyRun_SimpleString);
    privload_relocate_mod_takelock(mod);
}
#endif