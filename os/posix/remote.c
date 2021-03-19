#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "ezinject.h"
#include "log.h"

EZAPI remote_suspend(struct ezinj_ctx *ctx){
	kill(ctx->target, SIGSTOP);
	return 0;
}

EZAPI remote_wait(struct ezinj_ctx *ctx, int expected_signal){
	int rc;
	int status;
	do {
		rc = waitpid(ctx->target, &status, 0);
		if(rc < 0){
			PERROR("waitpid");
			return rc;
		}
	} while(rc != ctx->target);

	if(!WIFSTOPPED(status)){
		ERR("remote did not stop");
		return -1;
	}

	int signal = WSTOPSIG(status);
	DBG("got signal: %d (%s)", signal, strsignal(signal));

	if(expected_signal > 0){
		if(signal != expected_signal){
			ERR("remote_wait: %s", strsignal(rc));
			return -1;
		}
	}

	return status;
}