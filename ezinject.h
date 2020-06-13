#ifndef __EZINJECT_H
#define __EZINJECT_H

#include "config.h"
#include "ezinject_injcode.h"

#include <stdint.h>
#include <asm/ptrace.h>
#include <sys/user.h>

#define IS_IGNORED_SIG(x) ((x) == SIGUSR1 || (x) == SIGUSR2 || (x) >= SIGRTMIN)

#ifndef HAVE_SHM_EXEC
#define	SHM_EXEC	0100000	/* execution access */
#endif

#ifndef PTRACE_SETOPTIONS
#define PTRACE_SETOPTIONS 0x4200
#endif

#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD 1
#endif

#ifdef EZ_ARCH_MIPS
// the bundled pt_regs definition is wrong (https://www.linux-mips.org/archives/linux-mips/2014-07/msg00443.html)
// so we must provide our own

struct pt_regs2 {
	uint64_t regs[32];
	uint64_t lo;
	uint64_t hi;
	uint64_t cp0_epc;
	uint64_t cp0_badvaddr;
	uint64_t cp0_status;
	uint64_t cp0_cause;
} __attribute__ ((aligned (8)));

typedef struct pt_regs2 regs_t;
#else
typedef struct user regs_t;
#endif

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
	int num_wait_calls;
	pid_t target;
	ez_addr libc;
	ez_addr libdl;
	ez_addr syscall_insn;
	ez_addr syscall_stack;
	ez_addr libc_syscall;
	ez_addr libc_semop;
	ez_addr libc_dlopen;
#ifdef HAVE_DL_LOAD_SHARED_LIBRARY
	ez_addr uclibc_sym_tables;
	ez_addr uclibc_loaded_modules;
	ez_addr uclibc_mips_got_reloc;
	ez_addr uclibc_dl_fixup;
#endif
#ifdef DEBUG
	ez_addr libc_puts;
	ez_addr libc_putchar;
#endif
	off_t dlopen_offset;
	off_t dlclose_offset;
	off_t dlsym_offset;
	//off_t pthread_join_offset;
	ez_addr libc_clone;
	int shm_id;
	int sem_id;
	ez_addr mapped_mem;
};

struct ezinj_str {
	int len;
	char *str;
};

#define SC_HAS_ARG(sc, i) (sc.argmask & (1 << i))
#define SC_GET_ARG(sc, i) (SC_HAS_ARG(sc, i) ? sc.argv[i] : 0)
// nr, a0, a1, a2, a3
#define SC_MAX_ARGS 5

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
#endif