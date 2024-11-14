#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

void child_main() {
    printf("child\n");
}

void parent_main() {
    printf("parent\n");
}

int main(int argc, char** argv) {
    printf("start\n");
    int f = fork();
    if (f == 0) {
        // child
        child_main();
    } else if (f > 0) {
        // parent
        parent_main();

        int status;
        waitpid(f, &status, 0);
        printf("child status %d\n", status);
    } else {
        printf("error\n");
    }
    printf("end\n");
}
