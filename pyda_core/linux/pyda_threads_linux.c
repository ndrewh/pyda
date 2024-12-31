

#define STATIC_DRMGR_ONLY
#include "pyda_threads.h"

#include "dr_api.h"
#include "dr_tools.h"
#include "drmgr.h"
#include "Python.h"
#include "pyda_util.h"

#include "privload.h"

void* pyda_dlopen(const char *filename, int flag) {
    void *drcontext = dr_get_current_drcontext();
    // DEBUG_PRINTF("pyda_dlopen %s\n", filename);
    // DR_ASSERT(IS_CLIENT_THREAD(drcontext));
    if (filename == NULL) {
        void *retaddr = __builtin_return_address(0);
        privmod_t *mod = privload_lookup_by_pc_takelock(retaddr);
        if (mod != NULL)
            return mod->base;
        else
            return NULL;
    } else {
        return locate_and_load_private_library(filename, true);
    }
}

void* pyda_dlsym(void *handle, const char *symbol) {
    void *drcontext = dr_get_current_drcontext();
    // DEBUG_PRINTF("pyda_dlsym %s\n", symbol);
    // DR_ASSERT(IS_CLIENT_THREAD(drcontext));
    return get_private_library_address(handle, symbol);
}
