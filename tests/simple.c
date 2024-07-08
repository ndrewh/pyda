#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

int main(int argc, char** argv) {
    printf("start\n");
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
    printf("end\n");
}