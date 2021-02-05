#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>

#include "ezinject.h"
#include "ezinject_arch.h"
#include "log.h"

#ifndef PTRACE_GETREGS
// NT_PRSTATUS
#include <linux/elf.h>
#endif

EZAPI remote_attach(struct ezinj_ctx *ctx){
	return ptrace(PTRACE_ATTACH, ctx->target, 0, 0);
}

EZAPI remote_detach(struct ezinj_ctx *ctx){
	return ptrace(PTRACE_DETACH, ctx->target, 0, 0);
}

EZAPI remote_step(struct ezinj_ctx *ctx, int signal){
	return ptrace(PTRACE_SINGLESTEP, ctx->target, 0, signal);
}

EZAPI remote_continue(struct ezinj_ctx *ctx, int signal){
	return ptrace(PTRACE_CONT, ctx->target, 0, signal);
}

EZAPI remote_getregs(struct ezinj_ctx *ctx, regs_t *regs){
#ifdef PTRACE_GETREGS
	return ptrace(PTRACE_GETREGS, ctx->target, 0, regs);
#else
	struct iovec iovec = {
		.iov_base = regs,
		.iov_len = sizeof(*regs)
	};
	return ptrace(PTRACE_GETREGSET, ctx->target, (void*)NT_PRSTATUS, &iovec);
#endif
}

EZAPI remote_setregs(struct ezinj_ctx *ctx, regs_t *regs){
#ifdef PTRACE_SETREGS
	return ptrace(PTRACE_SETREGS, ctx->target, 0, regs);
#else
	struct iovec iovec = {
		.iov_base = regs,
		.iov_len = sizeof(*regs)
	};
	return ptrace(PTRACE_SETREGSET, ctx->target, (void*)NT_PRSTATUS, &iovec);
#endif
}

EZAPI remote_read(struct ezinj_ctx *ctx, void *dest, uintptr_t source, size_t size){
	uintptr_t *destWords = (uintptr_t *)dest;
	
	size_t read;
	for(read=0; read < size; read+=sizeof(uintptr_t), destWords++){
		*destWords = (uintptr_t)ptrace(PTRACE_PEEKTEXT, ctx->target, source + read, 0);
	}
	return read;
}

EZAPI remote_write(struct ezinj_ctx *ctx, uintptr_t dest, void *source, size_t size){
	uintptr_t *sourceWords = (uintptr_t *)source;
	
	size_t written;
	for(written=0; written < size; written+=sizeof(uintptr_t), sourceWords++){
		if(ptrace(PTRACE_POKETEXT, ctx->target, dest + written, *sourceWords) < 0){
			ERR("ptrace write failed at %p: %s", dest + written, strerror(errno));
		}
	}
	return written;
}