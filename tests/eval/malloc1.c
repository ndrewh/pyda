#include <stdlib.h>
int main() {
    for (int i=0; i<1; i++) {
        void *m = malloc(0x100);
        free(m);
    }
}
