#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#define UNUSED(x) (void)x

#include <iostream>

extern "C" {
	int func1(std::string &str) {
		std::cout << str << "\n";
		return str.size();
	}
}

void onSignal(int sigNum){
	UNUSED(sigNum);
	printf("Error: got signal %d (%s)\n", sigNum, strsignal(sigNum));
	raise(SIGSTOP);
}

int main(int argc, char *argv[])
{
	UNUSED(argv);
	signal(SIGSEGV, onSignal);

	std::string str = "Hello World";

	printf("pid=%d\n&main=%p\n&return2=%p\n", getpid(), main, func1);
	for(;;)
	{
		int val = func1(str);
		printf("return1() = %d\n", val);
		if(!val){
			break;
		}
		usleep(1000 * 1000);
	}
	return 0;
}
