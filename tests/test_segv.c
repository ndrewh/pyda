#include <stdio.h>

void segfault() {
    *(volatile int*)0 = 0;
}

int main() {
    printf("Hello, World!\n");
    segfault();
    return 0;
}