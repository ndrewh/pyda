
#include "dr_api.h"
#include "dr_tools.h"
#include "drmgr.h"
#include "privload.h"
#include "Python.h"
#include <pthread.h>
#include "util.h"

// These are used by python as shims to dynamorio-safe pthread functions

int pyda_thread_setspecific(pthread_key_t key, void *val);

int pyda_thread_key_create(pthread_key_t *p2newkey, void *unused) {
    int field = drmgr_register_tls_field();
    DR_ASSERT(field != -1);
    DEBUG_PRINTF("pthread_thread_key_create %d\n", field);
    *p2newkey = (pthread_key_t)field;
    pyda_thread_setspecific(field, 0);
    return 0;
}
int pyda_thread_key_delete(pthread_key_t key) {
    // nop
    return 0;
}
void* pyda_thread_getspecific(pthread_key_t key) {
    void *drcontext = dr_get_current_drcontext();
    void* result =  drmgr_get_tls_field(drcontext, (int)key);
    // DEBUG_PRINTF("pthread_thread_key_getspecific %d result %lx\n", key, (unsigned long)result);
    return result;
}
int pyda_thread_setspecific(pthread_key_t key, void *val) {
    void *drcontext = dr_get_current_drcontext();
    bool result = drmgr_set_tls_field(drcontext, (int)key, val);
    // DEBUG_PRINTF("pthread_thread_key_setspecific %d val %lx result %d\n", key, (unsigned long)val, result);
    return result != 1;
}

int pyda_cond_init(pthread_cond_t *condvar, const pthread_condattr_t *attr) {
    // DEBUG_PRINTF("pthread_cond_init %p\n", condvar);
    return pthread_cond_init(condvar, attr);
}
int pyda_cond_timedwait(pthread_cond_t *condvar, pthread_mutex_t *mutex, const struct timespec *abstime) {
    // DEBUG_PRINTF("pthread_cond_timedwait %p %p\n", condvar, mutex);
    // dr_set_safe_for_sync(false);
    int result = pthread_cond_timedwait(condvar, mutex, abstime);
    // dr_set_safe_for_sync(true);
    return result;
}
int pyda_cond_signal(pthread_cond_t *condvar) {
    // DEBUG_PRINTF("pthread_cond_signal %p\n", condvar);
    return pthread_cond_signal(condvar);
}

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