#include <stdio.h>

// Ignore this; it is just to help the challenge work on remote :)
void setup() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
}

int main() {
	setup();
	char decision[32];
	long coordinates;
	puts("I have put a ramjet on the little einstein's rocket ship");
	puts("However, I do not know WHERE to go on the next adventure!");
	printf("Quincy says somewhere around here might be fun... %p\n", &coordinates);
	fgets(decision, 48, stdin);
	return 0;
}

