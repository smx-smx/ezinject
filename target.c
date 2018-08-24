#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int return1(void)
{
	return 1;
}

int main(int argc, char *argv[])
{
	int interactive = argc > 1;
	printf("pid=%d\n&return1=%p\n", getpid(), return1);
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
