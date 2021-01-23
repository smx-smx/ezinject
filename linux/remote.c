#include <sys/types.h>
#include <asm/ptrace.h>
#include <sys/wait.h>

#include "ezinject.h"
#include "ezinject_arch.h"
#include "log.h"

int remote_attach(pid_t target){
	return ptrace(PTRACE_ATTACH, target, 0, 0);
}

int remote_detach(pid_t target){
	return ptrace(PTRACE_DETACH, target, 0, 0);
}

int remote_continue(pid_t target, int signal){
	return ptrace(PTRACE_CONT, target, 0, signal);
}

long remote_getregs(pid_t target, regs_t *regs){
#ifdef PTRACE_GETREGS
	return ptrace(PTRACE_GETREGS, target, 0, regs);
#else
	struct iovec iovec = {
		.iov_base = regs,
		.iov_len = sizeof(*regs)
	};
	return ptrace(PTRACE_GETREGSET, target, (void*)NT_PRSTATUS, &iovec);
#endif
}

long remote_setregs(pid_t target, regs_t *regs){
#ifdef PTRACE_SETREGS
	return ptrace(PTRACE_SETREGS, target, 0, regs);
#else
	struct iovec iovec = {
		.iov_base = regs,
		.iov_len = sizeof(*regs)
	};
	return ptrace(PTRACE_SETREGSET, target, (void*)NT_PRSTATUS, &iovec);
#endif
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

int remote_syscall_step(pid_t target){
	return ptrace(PTRACE_SYSCALL, target, 0, 0);
}

int remote_syscall_trace_enable(pid_t target, int enable){
	return 0;
}

size_t remote_read(struct ezinj_ctx *ctx, void *dest, uintptr_t source, size_t size){
	uintptr_t *destWords = (uintptr_t *)dest;
	
	size_t read;
	for(read=0; read < size; read+=sizeof(uintptr_t), destWords++){
		*destWords = (uintptr_t)ptrace(PTRACE_PEEKTEXT, ctx->target, source + read, 0);
	}
	return read;
}

size_t remote_write(struct ezinj_ctx *ctx, uintptr_t dest, void *source, size_t size){
	uintptr_t *sourceWords = (uintptr_t *)source;
	
	size_t written;
	for(written=0; written < size; written+=sizeof(uintptr_t), sourceWords++){
		if(ptrace(PTRACE_POKETEXT, ctx->target, dest + written, *sourceWords) < 0){
			PERROR("ptrace");
		}
	}
	return written;
}