#include <stdio.h>
#include <stdlib.h>

int main()
{
	void *p = malloc(1024 * 1024);
	printf("%p\n", p);
	free(p);
}