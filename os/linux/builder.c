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

#include "config.h"
#include "ezinject_util.h"
#include "ezinject.h"
#include "os/builder.h"
#include "log.h"

extern int push_string(struct ezinj_strings *strings, enum ezinj_str_id str_id, const char *str);

#define PUSH_STRING(id, str) do { \
	if(push_string(strings, id, str) < 0) return; \
} while(0)

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
	if(result == 0){
		ctx->force_mmap_syscall = 1;
		WARN("mmap(3) failed, trying mmap(2)");
		result = remote_pl_alloc(ctx, mapping_size);
	}
	return result;
}

int os_pl_copy(struct ezinj_ctx *ctx, size_t mapping_size){
	UNUSED(mapping_size);
	return remote_pl_copy(ctx);
}

bool os_should_retry(struct ezinj_ctx *ctx, int err){
	UNUSED(ctx);
	return (err == INJ_ERR_LIBDL);
}

void os_strings_init(struct ezinj_ctx *ctx, struct ezinj_strings *strings, struct os_builder_ctx *os_ctx){
	UNUSED(ctx);
	memset(os_ctx, 0, sizeof(*os_ctx));

	off_t pl_filename_offset = strings->dyn_str_size;
	char *pl_filename = tempnam(NULL, "ezpl");
	if(pl_filename == NULL){
		PERROR("tmpnam");
		return;
	}
	os_ctx->pl_filename = pl_filename;

	PUSH_STRING(EZSTR_PL_FILENAME, pl_filename);

	PUSH_STRING(EZSTR_API_DLERROR, "dlerror");
	PUSH_STRING(EZSTR_API_PTHREAD_MUTEX_INIT, "pthread_mutex_init");
	PUSH_STRING(EZSTR_API_PTHREAD_MUTEX_LOCK, "pthread_mutex_lock");
	PUSH_STRING(EZSTR_API_PTHREAD_MUTEX_UNLOCK, "pthread_mutex_unlock");
	PUSH_STRING(EZSTR_API_COND_INIT, "pthread_cond_init");
	PUSH_STRING(EZSTR_API_COND_WAIT, "pthread_cond_wait");
}

void os_bearing_setup(struct injcode_bearing *br, struct ezinj_ctx *ctx, struct os_builder_ctx *os_ctx){
	UNUSED(os_ctx);

	br->libc_dlopen.fptr = (void *)ctx->libc_dlopen.remote;
	br->libc_dlopen.got = (void *)ctx->libdl_got.remote;

	br->libc_syscall.fptr = (void *)ctx->libc_syscall.remote;
	br->libc_syscall.got = (void *)ctx->libc_got.remote;

	DBGPTR(br->libc_dlopen.fptr);
	DBGPTR(br->libc_dlopen.got);
	DBGPTR(br->libc_syscall.fptr);

	br->libc_got = (void *)ctx->libc_got.remote;
	br->libdl_got = (void *)ctx->libdl_got.remote;

#ifdef HAVE_DL_LOAD_SHARED_LIBRARY
	br->uclibc_sym_tables = (void *)ctx->uclibc_sym_tables.remote;
	br->uclibc_dl_fixup.fptr = (void *)ctx->uclibc_dl_fixup.remote;
	br->uclibc_loaded_modules = (void *)ctx->uclibc_loaded_modules.remote;
#ifdef EZ_ARCH_MIPS
	br->uclibc_mips_got_reloc.fptr = (void *)ctx->uclibc_mips_got_reloc.remote;
#endif
#endif
}

void os_rcall_setup(struct ezinj_ctx *ctx, struct injcode_call *rcall, uintptr_t r_call_args){
	rcall->libc_syscall.fptr = (void *)ctx->libc_syscall.remote;
	rcall->libc_syscall.got = (void *)ctx->libc_got.remote;
	rcall->libc_syscall.self = (void *)r_call_args + offsetof(struct injcode_call, libc_syscall);

	if(ctx->force_mmap_syscall){
		rcall->libc_mmap.fptr = NULL;
	} else {
		rcall->libc_mmap.fptr = (void *)ctx->libc_mmap.remote;
	}
	rcall->libc_mmap.got = (void *)ctx->libc_got.remote;
	rcall->libc_mmap.self = (void *)r_call_args + offsetof(struct injcode_call, libc_mmap);

	rcall->libc_open.fptr = (void *)ctx->libc_open.remote;
	rcall->libc_open.got = (void *)ctx->libc_got.remote;
	rcall->libc_open.self = (void *)r_call_args + offsetof(struct injcode_call, libc_open);

	rcall->libc_read.fptr = (void *)ctx->libc_read.remote;
	rcall->libc_read.got = (void *)ctx->libc_got.remote;
	rcall->libc_read.self = (void *)r_call_args + offsetof(struct injcode_call, libc_read);
}
