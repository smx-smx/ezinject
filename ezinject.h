#ifndef __EZINJECT_H
#define __EZINJECT_H

#include "config.h"

#include <stdint.h>
#include <stddef.h>

#ifndef EZ_TARGET_FREEBSD
#include <asm/ptrace.h>
#endif

#include <sys/types.h>
#include <sys/user.h>

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

struct ezinj_ctx {
	int pl_debug;
	int num_wait_calls;
	pid_t target;
	uintptr_t target_codebase;
	ez_addr libc;
	ez_addr libdl;
	ez_addr syscall_insn;
	ez_addr syscall_stack;
	ez_addr libc_syscall;
	ez_addr libc_dlopen;
#ifdef DEBUG
	ez_addr libc_printf;
#endif
#ifdef HAVE_DL_LOAD_SHARED_LIBRARY
	ez_addr uclibc_sym_tables;
	ez_addr uclibc_loaded_modules;
	ez_addr uclibc_mips_got_reloc;
	ez_addr uclibc_dl_fixup;
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

#define SC_HAS_ARG(sc, i) (sc.argmask & (1 << i))
#define SC_GET_ARG(sc, i) (SC_HAS_ARG(sc, i) ? sc.argv[i] : 0)
// nr, a0, a1, a2, a3, a4, a5, a6
#define SC_MAX_ARGS 8

struct sc_req {
	unsigned int argmask;
	uintptr_t argv[SC_MAX_ARGS];
};

struct call_req {
	uintptr_t insn_addr;
	uintptr_t stack_addr;
	struct sc_req syscall;
	int num_wait_calls;
};

ez_addr sym_addr(void *handle, const char *sym_name, ez_addr lib);

/** remote API **/
#include "ezinject_arch.h"
int remote_attach(pid_t target);
int remote_detach(pid_t target);
int remote_continue(pid_t target, int signal);
long remote_getregs(pid_t target, regs_t *regs);
long remote_setregs(pid_t target, regs_t *regs);
int remote_wait(pid_t target);
size_t remote_read(struct ezinj_ctx *ctx, void *dest, uintptr_t source, size_t size);
size_t remote_write(struct ezinj_ctx *ctx, uintptr_t dest, void *source, size_t size);
int remote_syscall_step(pid_t target);
int remote_syscall_trace_enable(pid_t target, int enable);
#endif