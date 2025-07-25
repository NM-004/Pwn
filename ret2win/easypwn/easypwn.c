
// easypwn.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win() {
    printf("Well done! Here's your flag:\n");
    system("cat flag.txt");
}

void vuln() {
    char buffer[64];
    printf("Enter something funny: ");
    gets(buffer);  // vulnerable function
    printf("You Entered: %s\n", buffer);
}

int main() {
    vuln();
    return 0;
}

