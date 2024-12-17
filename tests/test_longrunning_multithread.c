
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdint.h>
#include <pthread.h>

unsigned long timems() {
  struct timeval start;
  gettimeofday(&start, NULL);
  return (start.tv_sec * 1000000 + start.tv_usec) / 1000;
}

void* thread(void *tid) {
    unsigned int t = (unsigned int)(unsigned long)tid;
    printf("Hello from long running test %u\n", t);
    unsigned long start = timems();
    while (timems() - start < 10000) {
        sleep(1);
    }
    char *buf = malloc(100);
    snprintf(buf, 100, "Finished longrunning test %u\n", t);
    printf("%s", buf);
    return NULL;
}

int main() {
    pthread_t threads[10];
    for (int i=0; i<10; i++) {
        pthread_create(&threads[i], 0, thread, (void*)(uintptr_t)i);
    }

    for (int i=0; i<10; i++) {
        void *ret;
        pthread_join(threads[i], &ret);
    }


}
