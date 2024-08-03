#include <stdio.h>
#include <stdlib.h>
int main() {
    printf("hello there. please enter your name:\n");
    char *name = malloc(100000000); // 100M
    int res = fread(name, 1, 100000000, stdin);
    if (res != 100000000) {
        printf("error reading name\n");
        return 1;
    }
    printf("hello, %s\n", name);
    free(name);
    printf("goodbye\n");
}