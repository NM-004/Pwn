#include <stdio.h>
#include <string.h>

void win(){
	printf("You win");
	exit(0);
}

void vuln(){
	char buffer[64];
	printf("Enter your input: ");
	gets(buffer);
	printf("You entered: %s\n",buffer);
}

int main(){
	vuln();
	return 0;
}
