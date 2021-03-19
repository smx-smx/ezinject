#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <dlfcn.h>

#define UNUSED(x) (void)x

int return1(void)
{
	return 1;
}

void func2(void)
{
	puts("Func2 called!");
}

void onSignal(int sigNum){
	UNUSED(sigNum);
	#ifdef HAVE_STRSIGNAL
	printf("Error: got signal %d (%s)\n", sigNum, strsignal(sigNum));
	#else
	printf("Error: got signal %d\n", sigNum);
	#endif
	raise(SIGSTOP);
}

int main(int argc, char *argv[])
{
	UNUSED(argv);
	signal(SIGSEGV, onSignal);

	//signal(SIGTRAP, onSignal);

	void *self = dlopen(NULL, RTLD_NOW);
	printf("self: %p\n", self);

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
