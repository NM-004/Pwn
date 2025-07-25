#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void win(char *a, char *b) {
    if (!strcmp(a, "supersecret") && !strcmp(b, "ultrasecret")) {
        system("cat flag.txt");
    } else {
        puts("Wrong secrets!");
    }
}

void vuln() {
    char buf[64];
    puts("Enter your input:");
    read(0, buf, 200);  // Buffer overflow here
}

int main() {
    vuln();
    return 0;
}

