#include <unistd.h>
#include <signal.h>
#include <sys/types.h>

#include "ezinject.h"

EZAPI remote_suspend(struct ezinj_ctx *ctx){
	kill(ctx->target, SIGSTOP);
	return 0;
}