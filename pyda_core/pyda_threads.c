// We use this so that we have dr_set_tls_field
#define STATIC_DRMGR_ONLY
#include "pyda_threads.h"

#include "dr_api.h"
#include "dr_tools.h"
#include "drmgr.h"
#include "Python.h"
#include "pyda_util.h"

#ifdef LINUX
#include <sys/auxv.h>
#endif

#ifdef UNIX
#include <semaphore.h>
#include <unistd.h>
#endif

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
    int res;
    if (attr) {
#ifdef LINUX
        pthread_condattr_setpshared((pthread_condattr_t*)attr, PTHREAD_PROCESS_SHARED);
#endif
        res = pthread_cond_init(condvar, attr);
    } else {
        pthread_condattr_t attr2;
        pthread_condattr_init(&attr2);
#ifdef LINUX
        pthread_condattr_setpshared(&attr2, PTHREAD_PROCESS_SHARED);
#endif
        res = pthread_cond_init(condvar, &attr2);
        pthread_condattr_destroy(&attr2);
    }

    return res;
}
int pyda_cond_timedwait(pthread_cond_t *condvar, pthread_mutex_t *mutex, const struct timespec *abstime) {
    // DEBUG_PRINTF("pthread_cond_timedwait %p %p ids %d\n", condvar, mutex, getpid());
    int result = pthread_cond_timedwait(condvar, mutex, abstime);
    return result;
}
int pyda_cond_signal(pthread_cond_t *condvar) {
    // DEBUG_PRINTF("pthread_cond_signal %p ids %d\n", condvar, getpid());
    return pthread_cond_signal(condvar);
}

int pyda_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
    // DEBUG_PRINTF("pthread_mutex_init %p\n", mutex);
    int res;
    if (attr) {
#ifdef LINUX
        pthread_mutexattr_setpshared((pthread_mutexattr_t*)attr, PTHREAD_PROCESS_SHARED);
#endif
        res = pthread_mutex_init(mutex, attr);
    } else {
        pthread_mutexattr_t attr2;
        pthread_mutexattr_init(&attr2);
#ifdef LINUX
        pthread_mutexattr_setpshared(&attr2, PTHREAD_PROCESS_SHARED);
#endif
        res = pthread_mutex_init(mutex, &attr2);
        pthread_mutexattr_destroy(&attr2);
    }

    return res;
}

void* pyda_thread_self() {
    // XXX: We *could* try to return our pyda-specific tid -- but there
    // are technically two threads with that tid!! (Python and App).
    // If we returned the same ID for two python threads,
    // it seems likely it would break things.
    //
    // Instead, we are just going to return the dynamorio thread id
    return (void*)(uintptr_t)dr_get_thread_id(dr_get_current_drcontext());
}

extern void __ctype_init();
void* python_thread_init(void *pyda_thread) {
#ifdef LINUX
    __ctype_init();
#endif

    void *drcontext = dr_get_current_drcontext();
    void *tls = dr_thread_alloc(drcontext, sizeof(void*) * 130);
    memset(tls, 0, sizeof(void*) * 130);
    dr_set_tls_field(drcontext, (void *)tls);

    dr_client_thread_set_suspendable(false);
    pyda_thread_setspecific(g_pyda_tls_idx, (void*)pyda_thread);
    pyda_thread_setspecific(g_pyda_tls_is_python_thread_idx, (void*)1);
    return tls;
}

struct thread_start {
    void *(*start_routine) (void *);
    void *arg;
    // void *pyda_thread;
};

static void client_thread_init(void *arg) {
    struct thread_start *ts = (struct thread_start*)arg;
    void *tls = python_thread_init(NULL);
    ts->start_routine(ts->arg);
    DEBUG_PRINTF("start_routine returned\n");
    dr_client_thread_set_suspendable(true);
    dr_thread_free(dr_get_current_drcontext(), tls, sizeof(void*) * 130);
    dr_global_free(ts, sizeof(struct thread_start));
}

int pyda_thread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg) {
    DEBUG_PRINTF("pthread_create %p %p %p %p\n", thread, attr, start_routine, arg);

    struct thread_start *ts = dr_global_alloc(sizeof(struct thread_start));
    ts->start_routine = start_routine;
    ts->arg = arg;
    // ts->pyda_thread = pyda_thread_getspecific(g_pyda_tls_idx);
    dr_create_client_thread(client_thread_init, ts);
    *thread = (pthread_t)0x13371337;
    return 0;
}

int pyda_thread_detach(pthread_t thread) {
    // nop
    DEBUG_PRINTF("pthread_detach %p\n", thread);
    return 0;
}

#ifdef LINUX

extern size_t os_minsigstksz(void);
unsigned long pyda_getauxval(unsigned long type) {
    DEBUG_PRINTF("getauxval %lx\n", type);
    if (type == AT_MINSIGSTKSZ) {
        return os_minsigstksz();
    }
    return getauxval(type);
}

#endif

int pyda_attach_mode;

extern const char *our_getenv(const char *name);
const char *pyda_getenv(const char *name) {
    // Dynamorio does not have the correct ENV in attach mode.
    DEBUG_PRINTF("getenv2 %s=%s\n", name, getenv(name));
    return getenv(name);
}

void parse_proc_environ() {
    FILE *f = fopen("/proc/self/environ", "r");
    if (!f) {
        DEBUG_PRINTF("Failed to open /proc/self/environ\n");
        return;
    }

    // /proc/self/environ is a NULL-separated list of strings
    // each of the form KEY=VALUE

    // We store the new environment in attach_env
    // and we will use that in the attach mode.

    char buf[4096];
    size_t len = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    if (len == sizeof(buf)) {
        DEBUG_PRINTF("Warning: /proc/self/environ too large\n");
    }

    char *key = buf;
    while (key < buf + len) {
        char *k = strtok(key, "=");
        char *v = key + strlen(k) + 1;
        DEBUG_PRINTF("setenv %s=%s\n", k, v);
        setenv(k, v, 0);
        key = v + strlen(v) + 1;
    }

}

/* void pyda_sigaltstack(void *a, void *b) { */
/*     DEBUG_PRINTF("sigaltstack %p %p\n", a, b); */
/* } */

int pyda_sysconf(int num) {
    /* DEBUG_PRINTF("sysconf %d\n", num); */
#ifdef LINUX
    if (num == _SC_SIGSTKSZ) {
        DEBUG_PRINTF("sigconf(_SC_SIGSTKSZ)\n");
        return os_minsigstksz();
    }
#endif
    return sysconf(num);
}

#ifdef UNIX
int pyda_sem_init(void *sem, int pshared, unsigned int value) {
    /* DEBUG_PRINTF("sem_init %p %d %d\n", sem, pshared, value); */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    return sem_init(sem, 1, value);
#pragma GCC diagnostic pop
}
#endif
