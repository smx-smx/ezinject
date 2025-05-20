/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#ifndef __EZINJECT_H
#define __EZINJECT_H

#include "config.h"

#include <stdint.h>
#include <stddef.h>

#include <sys/types.h>

#ifdef EZ_TARGET_LINUX
#include <asm/ptrace.h>
#include <sys/user.h>
#endif

#ifdef EZ_TARGET_DARWIN
#include <mach/mach.h>
#endif

#include "log.h"
#include "ezinject_injcode.h"

typedef struct {
	uintptr_t remote;
	uintptr_t local;
} ez_addr;

typedef struct {
	void *start;
	void *end;
} ez_region;

#define REGION_LENGTH(r) PTRDIFF((r).end, (r).start)

// base.local + (addr - remote.base)
#define EZ_LOCAL(ref, remote_addr) (ref.local + (PTRDIFF(remote_addr, ref.remote)))
// base.remote - (addr - local.base)
#define EZ_REMOTE(ref, local_addr) (ref.remote + (PTRDIFF(local_addr, ref.local)))

extern ez_region region_pl_code;

#ifdef HAVE_SHELLCODE
extern ez_region region_sc_code;
#endif

struct ezinj_pl {
	uint8_t *br_start;
	uint8_t *code_start;
	uint8_t *stack_top;
};

struct ezinj_ctx;

#define PL_REMOTE(ctx, addr) (ctx->mapped_mem.remote + PTRDIFF(addr, ctx->mapped_mem.local))
#define PL_REMOTE_CODE(ctx, addr) PL_REMOTE(ctx, ctx->pl.code_start) + PTRDIFF(addr, region_pl_code.start)

typedef EZAPI (*pfnCallHandler)(struct ezinj_ctx *ctx, struct injcode_call *rcall);

struct ezinj_ctx_plapi {
	uintptr_t inj_memset;
	uintptr_t inj_puts;
	uintptr_t inj_dchar;
	uintptr_t inj_dbgptr;
	uintptr_t inj_fetchsym;
};

struct ezinj_ctx {
	int pl_debug;
	int syscall_mode;
	pid_t target;
	uintptr_t r_xpage_base;
	char *module_logfile;
#ifdef EZ_TARGET_WINDOWS
	int wait_call_seq;
	DEBUG_EVENT ev;
	HANDLE hProc;
	HANDLE hThread;
	DWORD target_tid;
	uintptr_t r_ezstate_addr;
#endif
#ifdef EZ_TARGET_DARWIN
	task_t task;
	thread_t thread;
	// $FIXME: this is kind of a hack, but we only do one allocation
	// the better idea would be to add a `size` parameter to `remote_pl_free`
	size_t last_alloc_size;
#endif
#if defined(EZ_TARGET_LINUX) || defined(EZ_TARGET_FREEBSD) || defined(EZ_TARGET_WINDOWS) \
|| defined(EZ_TARGET_DARWIN)
	// holds the overwritten ELF header
	uint8_t *saved_sc_data;
	ssize_t saved_sc_size;
	int force_mmap_syscall;
#endif
	ez_addr libc;
	ez_addr libdl;
	ez_addr entry_insn;
	ez_addr branch_target;
	ez_addr pl_stack;
	pfnCallHandler rcall_handler_pre;
	pfnCallHandler rcall_handler_post;
	ez_addr libc_syscall;
	ez_addr libc_dlopen;
#ifdef EZ_TARGET_DARWIN
	ez_addr pthread_create_from_mach_thread;
	ez_addr pthread_create;
	ez_addr pthread_join;
	ez_addr pthread_detach;
	ez_addr pthread_self;
	ez_addr mach_thread_self;
	ez_addr task_self_trap;
	ez_addr mach_port_allocate;
	ez_addr thread_terminate;
#endif
#ifdef EZ_TARGET_LINUX
	ez_addr libc_mmap;
	ez_addr libc_open;
	ez_addr libc_read;
	ez_addr libc_close;
#endif
#ifdef HAVE_DL_LOAD_SHARED_LIBRARY
	ez_addr uclibc_sym_tables;
	ez_addr uclibc_loaded_modules;
	ez_addr uclibc_mips_got_reloc;
	ez_addr uclibc_dl_fixup;
#endif
#ifdef EZ_TARGET_WINDOWS
	ez_addr virtual_alloc;
	ez_addr virtual_free;
	ez_addr suspend_thread;
	ez_addr get_current_thread;
	ez_addr write_file;
	ez_addr nt_register_dll_noti;
	ez_addr nt_unregister_dll_noti;
#endif
	ptrdiff_t dlopen_offset;
	ptrdiff_t dlclose_offset;
	ptrdiff_t dlsym_offset;
	ez_addr libc_clone;
	int shm_id;
	int sem_id;
	ez_addr mapped_mem;

	struct ezinj_pl pl;
	struct ezinj_ctx_plapi plapi;
};

#define CALL_HAS_ARG(call, i) ((call).argmask & (1 << i))
#define CALL_GET_ARG(call, i) (CALL_HAS_ARG(call, i) ? (call).argv[i] : 0)
// nr, a0, a1, a2, a3, a4, a5, a6
#define CALL_MAX_ARGS 8

#define ARGMASK(x, i) (x | (1 << (i)))
#define CALL_0ARGS ARGMASK(0, 0)
#define CALL_1ARGS ARGMASK(CALL_0ARGS, 1)
#define CALL_2ARGS ARGMASK(CALL_1ARGS, 2)
#define CALL_3ARGS ARGMASK(CALL_2ARGS, 3)
#define CALL_4ARGS ARGMASK(CALL_3ARGS, 4)
#define CALL_5ARGS ARGMASK(CALL_4ARGS, 5)
#define CALL_6ARGS ARGMASK(CALL_5ARGS, 6)

#define __RCALL(ctx, argmask, ...) remote_call(ctx, argmask, ##__VA_ARGS__)
#define __RCALL_SC(ctx, nr, argmask, ...) __RCALL(ctx, argmask, nr, ##__VA_ARGS__)

// Remote System Call
#define RSCALL0(ctx,nr)               __RCALL_SC(ctx,nr,CALL_0ARGS)
#define RSCALL1(ctx,nr,a1)            __RCALL_SC(ctx,nr,CALL_1ARGS,UPTR(a1))
#define RSCALL2(ctx,nr,a1,a2)         __RCALL_SC(ctx,nr,CALL_2ARGS,UPTR(a1),UPTR(a2))
#define RSCALL3(ctx,nr,a1,a2,a3)      __RCALL_SC(ctx,nr,CALL_3ARGS,UPTR(a1),UPTR(a2),UPTR(a3))
#define RSCALL4(ctx,nr,a1,a2,a3,a4)   __RCALL_SC(ctx,nr,CALL_4ARGS,UPTR(a1),UPTR(a2),UPTR(a3),UPTR(a4))
#define RSCALL5(ctx,nr,a1,a2,a3,a4,a5) __RCALL_SC(ctx,nr,CALL_5ARGS,UPTR(a1),UPTR(a2),UPTR(a3),UPTR(a4),UPTR(a5))
#define RSCALL6(ctx,nr,a1,a2,a3,a4,a5,a6) __RCALL_SC(ctx,nr,CALL_6ARGS,UPTR(a1),UPTR(a2),UPTR(a3),UPTR(a4),UPTR(a5),UPTR(a6))

struct call_req {
	uintptr_t insn_addr;
	uintptr_t stack_addr;

	unsigned int argmask;
	uintptr_t argv[CALL_MAX_ARGS];
	int syscall_mode;

	uintptr_t backup_addr;
	uint8_t *backup_data;
	ssize_t backup_size;

	struct injcode_call rcall;
};

ez_addr sym_addr(void *handle, const char *sym_name, ez_addr lib);

/** remote API **/
#include "ezinject_arch.h"

EZAPI remote_call(
	struct ezinj_ctx *ctx,
	unsigned int argmask, ...
);

/** attach api **/
EZAPI remote_attach(struct ezinj_ctx *ctx);
EZAPI remote_detach(struct ezinj_ctx *ctx);
EZAPI remote_suspend(struct ezinj_ctx *ctx);
EZAPI remote_continue(struct ezinj_ctx *ctx, int signal);
EZAPI remote_step(struct ezinj_ctx *ctx, int signal);
EZAPI remote_getregs(struct ezinj_ctx *ctx, regs_t *regs);
EZAPI remote_setregs(struct ezinj_ctx *ctx, regs_t *regs);
EZAPI remote_wait(struct ezinj_ctx *ctx, int expected_signal);
EZAPI remote_read(struct ezinj_ctx *ctx, void *dest, uintptr_t source, size_t size);
EZAPI remote_write(struct ezinj_ctx *ctx, uintptr_t dest, void *source, size_t size);

/** injection api **/
uintptr_t remote_pl_alloc(struct ezinj_ctx *ctx, size_t mapping_size);
EZAPI remote_pl_copy(struct ezinj_ctx *ctx);
EZAPI remote_pl_free(struct ezinj_ctx *ctx, uintptr_t remote_shmaddr);

#define SC_ALLOC_ELFHDR (1 << 0)
#define SC_ALLOC_MMAP (1 << 1)

EZAPI remote_sc_alloc(struct ezinj_ctx *ctx, int flags, uintptr_t *sc_base);
EZAPI remote_sc_check(struct ezinj_ctx *ctx);
EZAPI remote_call_prepare(struct ezinj_ctx *ctx, struct injcode_call *call);
EZAPI remote_sc_free(struct ezinj_ctx *ctx, int flags, uintptr_t sc_base);
EZAPI remote_sc_set(struct ezinj_ctx *ctx, uintptr_t sc_base);
uintptr_t remote_sc_get_trap_start();
uintptr_t remote_sc_get_trap_stop();

/** libc/util api **/
EZAPI os_api_init(struct ezinj_ctx *ctx);
EZAPI resolve_libc_symbols(struct ezinj_ctx *ctx);
void *get_base(pid_t pid, char *substr, char **ignores);
#endif
