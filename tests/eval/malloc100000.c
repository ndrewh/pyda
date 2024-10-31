#include <stdlib.h>
int main() {
    for (int i=0; i<100000; i++) {
        void *m = malloc(0x100);
        free(m);
    }
}
