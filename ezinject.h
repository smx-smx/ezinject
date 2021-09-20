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

#include "ezinject_compat.h"
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

struct ezinj_pl {
	uint8_t *br_start;
	uint8_t *code_start;
	uint8_t *stack_top;
};

struct ezinj_ctx;

typedef EZAPI (*pfnCallHandler)(struct ezinj_ctx *ctx, struct injcode_call *rcall);

struct ezinj_ctx {
	int pl_debug;
	int syscall_mode;
	pid_t target;
#ifdef EZ_TARGET_WINDOWS
	DEBUG_EVENT ev;
	HANDLE hProc;
	HANDLE hThread;
#endif
#ifdef EZ_TARGET_DARWIN
	task_t task;
	thread_t thread;
#endif
#if defined(EZ_TARGET_LINUX) || defined(EZ_TARGET_FREEBSD)
	// holds the overwritten ELF header
	uint8_t *saved_sc_data;
	size_t saved_sc_size;
#endif
	uintptr_t target_codebase;
	ez_addr libc;
	ez_addr libdl;
	ez_addr trampoline_insn;
	ez_addr branch_target;
	ez_addr pl_stack;
	pfnCallHandler rcall_handler_pre;
	pfnCallHandler rcall_handler_post;
	ez_addr libc_syscall;
	ez_addr libc_dlopen;
#ifdef HAVE_DL_LOAD_SHARED_LIBRARY
	ez_addr uclibc_sym_tables;
	ez_addr uclibc_loaded_modules;
	ez_addr uclibc_mips_got_reloc;
	ez_addr uclibc_dl_fixup;
#endif
#ifdef EZ_TARGET_WINDOWS
	ez_addr nt_get_peb;
	ez_addr nt_query_proc;
	ez_addr nt_write_file;
#endif
	ptrdiff_t dlopen_offset;
	ptrdiff_t dlclose_offset;
	ptrdiff_t dlsym_offset;
	ez_addr libc_clone;
	int shm_id;
	int sem_id;
	ez_addr mapped_mem;

	struct ezinj_pl pl;
};

struct ezinj_str {
	unsigned int len;
	char *str;
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
	size_t backup_size;

	struct injcode_call rcall;
};

ez_addr sym_addr(void *handle, const char *sym_name, ez_addr lib);

/** remote API **/
#define EZAPI intptr_t

#include "ezinject_arch.h"

uintptr_t remote_call(
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
EZAPI remote_pl_free(struct ezinj_ctx *ctx, uintptr_t remote_shmaddr);

EZAPI remote_sc_alloc(struct ezinj_ctx *ctx);
EZAPI remote_sc_check(struct ezinj_ctx *ctx);
EZAPI remote_call_prepare(struct ezinj_ctx *ctx, struct injcode_call *call);
EZAPI remote_sc_free(struct ezinj_ctx *ctx);
#endif