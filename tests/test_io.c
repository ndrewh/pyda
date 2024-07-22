#include <stdio.h>
int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    printf("hello there. please enter your name:\n");
    char name[100];
    scanf("%s", name);
    printf("hello, %s\n", name);

    int age;
    printf("please enter your age:\n");
    scanf("%d", &age);
    printf("hello %s, you are %d years old\n", name, age);
    printf("goodbye\n");
}