// canary.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((naked)) void pop_rdi_ret() {
    __asm__("pop %rdi; ret;");
}

void win(char *secret) {
    if (strcmp(secret, "supersecret") == 0) {
        printf("🎉 Flag: CTF{stack_canary_success}\n");
        exit(0);
    } else {
        puts("Wrong password!");
    }
}

void vuln() {
    char buf[72];
    printf("Enter your input: ");
    gets(buf); // vulnerability
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("Welcome to the Canary Challenge!");
    vuln();
    return 0;
}

