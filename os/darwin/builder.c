/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "config.h"
#include "ezinject_util.h"
#include "ezinject.h"
#include "os/builder.h"
#include "log.h"

void os_pagesize_init(struct ezinj_ctx *ctx){
	ctx->pagesize = getpagesize();
}

int os_post_attach_wait(struct ezinj_ctx *ctx){
	return remote_wait(ctx, 0);
}

bool os_forward_signal(struct ezinj_ctx *ctx, int status, bool syscall_mode){
	int signal = WSTOPSIG(status);
	DBG("signal: %d", signal);
	if(!syscall_mode && (signal == SIGCHLD || signal == SIGUSR1 || signal == SIGUSR2 || signal >= 32)){
		INFO("forwarding signal %d", signal);
		remote_continue(ctx, signal);
		return true;
	}
	return false;
}

void os_invoke_begin(struct ezinj_ctx *ctx, struct injcode_call *rcall){
	UNUSED(ctx);
	UNUSED(rcall);
}

uintptr_t os_alloc_retry(struct ezinj_ctx *ctx, uintptr_t result, size_t mapping_size){
	UNUSED(ctx);
	UNUSED(mapping_size);
	return result;
}

int os_pl_copy(struct ezinj_ctx *ctx, size_t mapping_size){
	struct injcode_bearing *br = (struct injcode_bearing *)ctx->mapped_mem.local;
	if(remote_write(ctx,
		ctx->mapped_mem.remote,
		(void *)ctx->mapped_mem.local,
		br->mapping_size
	) != br->mapping_size){
		PERROR("remote_write failed");
		return -1;
	}
	return 0;
}

bool os_should_retry(struct ezinj_ctx *ctx, int err){
	UNUSED(ctx);
	UNUSED(err);
	return false;
}

void os_strings_init(struct ezinj_ctx *ctx, struct ezinj_strings *strings, struct os_builder_ctx *os_ctx){
	UNUSED(ctx);
	UNUSED(strings);
	memset(os_ctx, 0, sizeof(*os_ctx));
}

void os_bearing_setup(struct injcode_bearing *br, struct ezinj_ctx *ctx, struct os_builder_ctx *os_ctx){
	UNUSED(os_ctx);
	br->platform.libc_dlopen.fptr = (void *)ctx->libc_dlopen.remote;
	br->platform.libc_dlopen.got = (void *)ctx->libdl_got.remote;
	br->libc_syscall.fptr = (void *)ctx->libc_syscall.remote;
	br->libc_syscall.got = (void *)ctx->libc_got.remote;
	DBGPTR(br->platform.libc_dlopen.fptr);
	DBGPTR(br->platform.libc_dlopen.got);
	DBGPTR(br->libc_syscall.fptr);
	br->libc_got = (void *)ctx->libc_got.remote;
	br->libdl_got = (void *)ctx->libdl_got.remote;

	br->platform.pthread_create = (void *)ctx->platform.pthread_create.remote;
	br->platform.pthread_join = (void *)ctx->platform.pthread_join.remote;
	br->platform.pthread_create_from_mach_thread = (void *)ctx->platform.pthread_create_from_mach_thread.remote;
	br->platform.pthread_detach = (void *)ctx->platform.pthread_detach.remote;
	br->platform.pthread_self = (void *)ctx->platform.pthread_self.remote;
	br->platform.mach_thread_self = (void *)ctx->platform.mach_thread_self.remote;
	br->platform.thread_terminate = (void *)ctx->platform.thread_terminate.remote;
	br->platform.mach_port_allocate = (void *)ctx->platform.mach_port_allocate.remote;
	br->platform.task_self_trap = (void *)ctx->platform.task_self_trap.remote;
}

void os_rcall_setup(struct ezinj_ctx *ctx, struct injcode_call *rcall, uintptr_t r_call_args){
	rcall->platform.libc_syscall.fptr = (void *)ctx->libc_syscall.remote;
	rcall->platform.libc_syscall.got = (void *)ctx->libc_got.remote;
	rcall->platform.libc_syscall.self = (void *)r_call_args + offsetof(struct injcode_call, platform.libc_syscall);
}

void os_plt_resolve(void){
	int fd = open("/tmp/invalid_file_path", 0);
	if(fd >= 0) close(fd);
	mmap(0, 0, 0, 0, -1, 0);
	syscall(__NR_getpid);
}

void os_print_maps(void){}
int  os_sc_init(struct ezinj_ctx *ctx, uintptr_t *r_sc_elf){ *r_sc_elf=0; return 0; }
int  os_sc_relocate(struct ezinj_ctx *ctx, uintptr_t r_sc_elf, uintptr_t *r_sc_vmem){ *r_sc_vmem=0; return 0; }
int  os_sc_cleanup_vmem(struct ezinj_ctx *ctx, uintptr_t *r_sc_elf, uintptr_t r_sc_vmem){ return 0; }
