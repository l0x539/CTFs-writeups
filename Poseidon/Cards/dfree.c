#include<stdio.h>

int main () {
	char *a = malloc(3);
	*a = 'H';
	free(a);
	free(a);
}

