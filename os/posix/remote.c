/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "config.h"
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
#ifdef HAVE_STRSIGNAL
	DBG("got signal: %d (%s)", signal, strsignal(signal));
#else
	DBG("got signal: %d", signal);
#endif

	if(expected_signal > 0){
		if(signal != expected_signal){
			ERR("remote_wait: expected %d, got %d",
				expected_signal, signal);
			return -1;
		}
	}

	return status;
}
