/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#ifndef __EZINJECT_OS_BUILDER_H
#define __EZINJECT_OS_BUILDER_H

#include <stdint.h>
#include <stdbool.h>
#include "ezinject.h"
#include "log.h"

struct os_builder_ctx {
	char *pl_filename;
};

int push_string(struct ezinj_strings *strings, enum ezinj_str_id str_id, const char *str);

void os_pagesize_init(struct ezinj_ctx *ctx);
int  os_post_attach_wait(struct ezinj_ctx *ctx);
void os_strings_init(struct ezinj_ctx *ctx, struct ezinj_strings *strings, struct os_builder_ctx *os_ctx);
void os_bearing_setup(struct injcode_bearing *br, struct ezinj_ctx *ctx, struct os_builder_ctx *os_ctx);
void os_rcall_setup(struct ezinj_ctx *ctx, struct injcode_call *rcall, uintptr_t r_call_args);
bool os_forward_signal(struct ezinj_ctx *ctx, int status, bool syscall_mode);
void os_invoke_begin(struct ezinj_ctx *ctx, struct injcode_call *rcall);
uintptr_t os_alloc_retry(struct ezinj_ctx *ctx, uintptr_t result, size_t mapping_size);
int  os_pl_copy(struct ezinj_ctx *ctx, size_t mapping_size);
bool os_should_retry(struct ezinj_ctx *ctx, int err);
void os_plt_resolve(void);
void os_print_maps(void);
int  os_sc_init(struct ezinj_ctx *ctx, uintptr_t *r_sc_elf);
int  os_sc_relocate(struct ezinj_ctx *ctx, uintptr_t r_sc_elf, uintptr_t *r_sc_vmem);
int  os_sc_cleanup_vmem(struct ezinj_ctx *ctx, uintptr_t *r_sc_elf, uintptr_t r_sc_vmem);

static inline void os_strings_posix(struct ezinj_strings *strings)
{
#if defined(EZ_TARGET_POSIX)
	push_string(strings, EZSTR_API_DLERROR, "dlerror");
	push_string(strings, EZSTR_API_PTHREAD_MUTEX_INIT, "pthread_mutex_init");
	push_string(strings, EZSTR_API_PTHREAD_MUTEX_LOCK, "pthread_mutex_lock");
	push_string(strings, EZSTR_API_PTHREAD_MUTEX_UNLOCK, "pthread_mutex_unlock");
	push_string(strings, EZSTR_API_COND_INIT, "pthread_cond_init");
	push_string(strings, EZSTR_API_COND_WAIT, "pthread_cond_wait");
#endif
}

static inline int os_sc_init_impl(struct ezinj_ctx *ctx, uintptr_t *r_sc_elf)
{
	*r_sc_elf = 0;
#ifdef HAVE_SHELLCODE
	INFO("target: allocating sc");
	if(remote_sc_alloc(ctx, SC_ALLOC_ELFHDR, r_sc_elf) != 0){
		ERR("remote_sc_alloc: failed to overwrite ELF header");
		return -1;
	}
	remote_sc_set(ctx, *r_sc_elf);
	ctx->syscall_mode = true;
	if(remote_sc_check(ctx) != 0){
		ERR("remote_sc_check failed");
		return -1;
	}
#endif
	return 0;
}

static inline int os_sc_relocate_impl(struct ezinj_ctx *ctx, uintptr_t r_sc_elf, uintptr_t *r_sc_vmem)
{
	*r_sc_vmem = 0;
#if !defined(HAVE_REMOTING) && defined(HAVE_SHELLCODE)
	INFO("target: relocating sc");
	if(remote_sc_alloc(ctx, SC_ALLOC_MMAP, r_sc_vmem) != 0){
		ERR("remote_sc_alloc: mmap failed");
		return -1;
	}
	remote_sc_set(ctx, *r_sc_vmem);
	if(remote_sc_free(ctx, SC_ALLOC_ELFHDR, r_sc_elf) != 0){
		ERR("remote_sc_free: ELF header restore failed");
		return -1;
	}
#endif
	return 0;
}

static inline int os_sc_cleanup_impl(struct ezinj_ctx *ctx, uintptr_t *r_sc_elf, uintptr_t r_sc_vmem)
{
#if !defined(HAVE_REMOTING) && defined(HAVE_SHELLCODE)
	if(remote_sc_alloc(ctx, SC_ALLOC_ELFHDR, r_sc_elf) != 0){
		ERR("remote_sc_alloc: failed to overwrite ELF header");
		return -1;
	}
	remote_sc_set(ctx, *r_sc_elf);
	if(remote_sc_free(ctx, SC_ALLOC_MMAP, r_sc_vmem) != 0){
		ERR("remote_sc_free: failed to free memory map");
		return -1;
	}
#endif
	return 0;
}

#endif
