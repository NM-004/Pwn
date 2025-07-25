#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Inject our ROP gadget directly into the binary
__asm__(".global pop_rdi_ret\n"
        "pop_rdi_ret:\n"
        "    pop %rdi\n"
        "    ret\n");

void win(char *input) {
    if (strcmp(input, "supersecret") == 0) {
        system("cat flag.txt");
    } else {
        puts("Wrong input.");
    }
}

void vuln(){
    char buf[64];
    gets(buf); // vulnerable
    printf("You entered: %s\n", buf);
}

int main() {
    vuln();
    return 0;
}

