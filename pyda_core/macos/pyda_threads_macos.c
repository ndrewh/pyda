

#define STATIC_DRMGR_ONLY
#include "pyda_threads.h"

#include "dr_api.h"
#include "dr_tools.h"
#include "drmgr.h"
#include "Python.h"
#include "pyda_util.h"

#include "privload.h"

#include <dlfcn.h>

void* pyda_dlopen(const char *filename, int flag) {
    /* NYI: private loader */
    return dlopen(filename, flag);
}

void* pyda_dlsym(void *handle, const char *symbol) {
    /* NYI: private loader */
    return dlsym(handle, symbol);
}
