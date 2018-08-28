#include <stdio.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void p(void)
{
	char str[]="hello world\n";
	write(1, str, sizeof(str)-1);
}
