#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "ezinject.h"
#include "ezinject_arch.h"
#include "log.h"

int remote_attach(pid_t target){
	return ptrace(PT_ATTACH, target, 0, 0);
}

int remote_detach(pid_t target){
	return ptrace(PT_DETACH, target, 0, 0);
}

int remote_continue(pid_t target, int signal){
	return ptrace(PT_CONTINUE, target, (caddr_t)1, signal);
}

long remote_getregs(pid_t target, regs_t *regs){
	return ptrace(PT_GETREGS, target, (caddr_t)regs, 0);
}

long remote_setregs(pid_t target, regs_t *regs){
	return ptrace(PT_SETREGS, target, (caddr_t)regs, 0);
}

int remote_wait(pid_t target){
	int rc;
	int status;
	do {
		rc = waitpid(target, &status, 0);
		if(rc < 0){
			PERROR("waitpid");
			return rc;
		}
	} while(rc != target);

	if(!WIFSTOPPED(status)){
		ERR("remote did not stop");
		return -1;
	}

	return status;
}

size_t remote_read(struct ezinj_ctx *ctx, void *dest, uintptr_t source, size_t size){
	uintptr_t *destWords = (uintptr_t *)dest;
	
	size_t read;
	for(read=0; read < size; read+=sizeof(uintptr_t), destWords++){
		*destWords = (uintptr_t)ptrace(PT_READ_D, ctx->target, (caddr_t)(source + read), 0);
	}
	return read;
}

size_t remote_write(struct ezinj_ctx *ctx, uintptr_t dest, void *source, size_t size){
	uintptr_t *sourceWords = (uintptr_t *)source;
	
	size_t written;
	for(written=0; written < size; written+=sizeof(uintptr_t), sourceWords++){
		ptrace(PT_WRITE_D, ctx->target, (caddr_t)(dest + written), *sourceWords);
	}
	return written;
}