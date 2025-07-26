// canary_leak_simple.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win() {
    printf("You win!\n");
    system("/bin/sh");
}

void vuln() {
    char buf[64];
    volatile unsigned long *canary = __builtin_frame_address(0) - 8;

    printf("Here’s your lucky number: %p\n", (void*)*canary); // simulate a leak

    printf("Enter something: ");
    gets(buf); // buffer overflow
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}

