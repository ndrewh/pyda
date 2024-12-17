
#include <unistd.h>
#include <sys/time.h>

unsigned long timems() {
  struct timeval start;
  gettimeofday(&start, NULL);
  return (start.tv_sec * 1000000 + start.tv_usec) / 1000;
}
int main() {
    printf("Hello from long running test\n");

    unsigned long start = timems();
    while (timems() - start < 10000) {
        sleep(1);
    }

    char *buf = malloc(100);
    snprintf(buf, 100, "Finished longrunning test\n");
    printf("%s", buf);
}
