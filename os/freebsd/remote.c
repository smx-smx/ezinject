/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>

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

EZAPI remote_step(struct ezinj_ctx *ctx, int signal){
	return ptrace(PT_STEP, ctx->target, (caddr_t)1, signal);
}

EZAPI remote_getregs(struct ezinj_ctx *ctx, regs_t *regs){
	return ptrace(PT_GETREGS, ctx->target, (caddr_t)regs, 0);
}

EZAPI remote_setregs(struct ezinj_ctx *ctx, regs_t *regs){
	return ptrace(PT_SETREGS, ctx->target, (caddr_t)regs, 0);
}

EZAPI remote_read(struct ezinj_ctx *ctx, void *dest, uintptr_t source, size_t size){
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
	struct ptrace_io_desc iov = {
		.piod_op = PIOD_WRITE_D,
		.piod_offs = (void *)dest,
		.piod_addr = source,
		.piod_len = size
	};

	ptrace(PT_IO, ctx->target, (caddr_t)&iov, 0);
	return iov.piod_len;
}
