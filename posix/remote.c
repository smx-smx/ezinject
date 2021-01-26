#include <unistd.h>
#include <signal.h>
#include <sys/types.h>

EZAPI remote_suspend(pid_t target){
	kill(target, SIGSTOP);
	return 0;
}