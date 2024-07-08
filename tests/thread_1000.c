#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#define NTHREAD 1000

void* thread(void* arg) {
    void *allocs[10];
    for (int i=0; i<10; i++) {
        allocs[i] = malloc(0x100);
    }
    for (int i=0; i<10; i++) {
        free(allocs[i]);
    }
    for (int i=0; i<10; i++) {
        allocs[i] = malloc(0x100);
    }
    for (int i=0; i<10; i++) {
        free(allocs[i]);
    }
}
int main(int argc, char** argv) {
    pthread_t threads[NTHREAD];
    for (int i=0; i<NTHREAD; i++) {
        pthread_create(&threads[i], 0, thread, 0);
    }

    for (int i=0; i<NTHREAD; i++) {
        void *ret;
        pthread_join(threads[i], &ret);
    }

    // thread(NULL);
    return 0;
}