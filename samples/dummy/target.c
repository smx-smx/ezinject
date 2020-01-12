#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int return1(void)
{
	return 1;
}

void func2(void)
{
	puts("Func2 called!");
}

int main(int argc, char *argv[])
{
	int interactive = argc > 1;
	printf("pid=%d\n&main=%p\n&return2=%p\n&func2=%p\n", getpid(), main, return1, func2);
	for(;;)
	{
		int val = return1();
		printf("return1() = %d\n", val);
		if(!val)
			break;
		if(interactive)
			fgetc(stdin);
		else
			usleep(1000 * 1000);
	}
	return 0;
}
