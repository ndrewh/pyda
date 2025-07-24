#include <stdio.h>
int main() {
    printf("hello there. please enter your name:\n");
    char name[100] = "tmp";
    scanf("%s", name);
    printf("hello, %s\n", name);

    int age;
    printf("please enter your age:\n");
    scanf("%d", &age);
    printf("hello %s, you are %d years old\n", name, age);
    printf("goodbye\n");
}
