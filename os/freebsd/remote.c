#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "ezinject.h"
#include "ezinject_arch.h"
#include "log.h"

EZAPI remote_attach(struct ezinj_ctx *ctx){
	return ptrace(PT_ATTACH, ctx->target, 0, 0);
}

EZAPI remote_detach(struct ezinj_ctx *ctx){
	return ptrace(PT_DETACH, ctx->target, 0, 0);
}

EZAPI remote_continue(struct ezinj_ctx *ctx, int signal){
	return ptrace(PT_CONTINUE, ctx->target, (caddr_t)1, signal);
}

EZAPI remote_getregs(struct ezinj_ctx *ctx, regs_t *regs){
	return ptrace(PT_GETREGS, ctx->target, (caddr_t)regs, 0);
}

EZAPI remote_setregs(struct ezinj_ctx *ctx, regs_t *regs){
	return ptrace(PT_SETREGS, ctx->target, (caddr_t)regs, 0);
}

EZAPI remote_wait(struct ezinj_ctx *ctx){
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

	return status;
}

EZAPI remote_syscall_step(struct ezinj_ctx *ctx){
	return ptrace(PT_SYSCALL, ctx->target, (caddr_t)1, 0);
}

EZAPI remote_syscall_trace_enable(struct ezinj_ctx *ctx, int enable){
	unsigned int mask = 0;
	if(ptrace(PT_GET_EVENT_MASK, ctx->target, (caddr_t)&mask, sizeof(mask)) < 0){
		PERROR("ptrace");
		return -1;
	}
	if(enable){
		mask = mask | PTRACE_SYSCALL;
	} else {
		mask = mask & ~PTRACE_SYSCALL;
	}
	if(ptrace(PT_SET_EVENT_MASK, ctx->target, (caddr_t)&mask, sizeof(mask)) < 0){
		PERROR("ptrace");
		return -1;
	}
	return 0;
}

EZAPI remote_read(struct ezinj_ctx *ctx, void *dest, uintptr_t source, size_t size){
	uintptr_t *destWords = (uintptr_t *)dest;
	
	struct ptrace_io_desc iov = {
		.piod_op = PIOD_READ_D,
		.piod_offs = (void *)source,
		.piod_addr = dest,
		.piod_len = size
	};
	ptrace(PT_IO, ctx->target, (caddr_t)&iov, 0);
	return iov.piod_len;
}

EZAPI remote_write(struct ezinj_ctx *ctx, uintptr_t dest, void *source, size_t size){
	uintptr_t *sourceWords = (uintptr_t *)source;
	
	struct ptrace_io_desc iov = {
		.piod_op = PIOD_WRITE_D,
		.piod_offs = (void *)dest,
		.piod_addr = source,
		.piod_len = size
	};

	ptrace(PT_IO, ctx->target, (caddr_t)&iov, 0);
	return iov.piod_len;
}