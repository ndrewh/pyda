
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
#ifndef MACOS
    { "pthread_cond_init", (app_pc)pyda_cond_init },
    { "pthread_cond_timedwait", (app_pc)pyda_cond_timedwait },
    { "pthread_cond_signal", (app_pc)pyda_cond_signal },
    { "pthread_mutex_init", (app_pc)pyda_mutex_init },
#endif
    { "pthread_self", (app_pc)pyda_thread_self },
    { "pthread_create", (app_pc)pyda_thread_create },
    { "pthread_detach", (app_pc)pyda_thread_detach },
    { "dlopen", (app_pc)pyda_dlopen },
    { "dlsym", (app_pc)pyda_dlsym },
#ifdef LINUX
    { "getauxval", (app_pc)pyda_getauxval },
    /* { "sigaltstack", (app_pc)pyda_sigaltstack }, */
    { "sysconf", (app_pc)pyda_sysconf },
#endif
    { "getenv", (app_pc)pyda_getenv },
    { "sem_init", (app_pc)pyda_sem_init }
};

#ifdef MACOS
extern void patch_macho(char *path, void *lib_base, redirect_import_t *redirects, int num_redirects);

// in dynamorio
extern void instrument_client_lib_loaded(void *start, void *end);
#endif

#define NUM_NEW_IMPORTS (sizeof(python_redirect_imports) / sizeof(redirect_import_t))
void patch_python() {
#ifdef LINUX
    client_redirect_imports = python_redirect_imports;
    client_redirect_imports_count = NUM_NEW_IMPORTS;
    privmod_t *mod = privload_lookup_by_pc_takelock((app_pc)&PyRun_SimpleString);
    privload_relocate_mod_takelock(mod);
#elif defined(MACOS)
    /* No private loader, so we just find the module and patch... */

    dr_module_iterator_t *iter = dr_module_iterator_start();
    while (dr_module_iterator_hasnext(iter)) {
        module_data_t *mod = dr_module_iterator_next(iter);
        if (strstr(mod->full_path, "libpython") != NULL) {
            void *lib_base = (void*)mod->start;
            patch_macho(mod->full_path, lib_base, python_redirect_imports, NUM_NEW_IMPORTS);
            instrument_client_lib_loaded(mod->start, mod->end);
            break;
        }
    }
    dr_module_iterator_stop(iter);

#endif
}
#endif
