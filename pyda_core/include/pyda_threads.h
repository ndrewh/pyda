#include <pthread.h>
extern int g_pyda_tls_idx;
extern int g_pyda_tls_is_python_thread_idx;
int pyda_thread_setspecific(pthread_key_t key, void *val);
void* pyda_thread_getspecific(pthread_key_t key);

int pyda_thread_key_create(pthread_key_t *p2newkey, void *unused);
int pyda_thread_key_delete(pthread_key_t key);
void* pyda_thread_getspecific(pthread_key_t key);
int pyda_thread_setspecific(pthread_key_t key, void *val);
int pyda_cond_init(pthread_cond_t *condvar, const pthread_condattr_t *attr);
int pyda_cond_timedwait(pthread_cond_t *condvar, pthread_mutex_t *mutex, const struct timespec *abstime);
int pyda_cond_signal(pthread_cond_t *condvar);
int pyda_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);

void* pyda_dlopen(const char *filename, int flag);
void* pyda_dlsym(void *handle, const char *symbol);
void* pyda_thread_self();
int pyda_thread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg);
int pyda_thread_detach(pthread_t thread);

void* python_thread_init(void *pyda_thread);
unsigned long pyda_getauxval(unsigned long type);
const char *pyda_getenv(const char *name);

void parse_proc_environ(void);
int pyda_sem_init(void *sem, int pshared, unsigned int value);
// void pyda_sigaltstack(void *a, void *b);
int pyda_sysconf(int num);
