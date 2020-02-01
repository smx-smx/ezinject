#ifndef __EZINJECT_H
#define __EZINJECT_H

#include "config.h"
#include "ezinject_injcode.h"

#include <sys/user.h>

#define UNUSED(x) (void)(x)
#define UPTR(x) ((uintptr_t)(x))


#define STRSZ(x) (strlen(x) + 1)
#define ALIGNMSK(y) ((y)-1)
#define ALIGN(x, y) ((void *)((UPTR(x) + ALIGNMSK(y)) & ~ALIGNMSK(y)))

#define MEMALIGN(x) ALIGN(x, sizeof(void *))

#ifdef EZ_ARCH_AMD64
//align to 16 bytes
#define STACKALIGN(x) ALIGN(x, 16)
#else
#define STACKALIGN(x) MEMALIGN(x)
#endif

#define PAGEALIGN(x)  ALIGN(x, getpagesize())

#define PTRDIFF(a, b) ( UPTR(a) - UPTR(b) )

#define IS_IGNORED_SIG(x) ((x) == SIGUSR1 || (x) == SIGUSR2 || (x) >= SIGRTMIN)

#ifndef HAVE_SHM_EXEC
#define	SHM_EXEC	0100000	/* execution access */
#endif

typedef struct {
	uintptr_t remote;
	uintptr_t local;
} ez_addr;

typedef struct {
	void *start;
	void *end;
} ez_region;

#define REGION_LENGTH(r) PTRDIFF(r.end, r.start)

// base.local + (addr - remote.base)
#define EZ_LOCAL(ref, remote_addr) (ref.local + (PTRDIFF(remote_addr, ref.remote)))
// base.remote - (addr - local.base)
#define EZ_REMOTE(ref, local_addr) (ref.remote + (PTRDIFF(local_addr, ref.local)))

struct ezinj_pl {
	struct injcode_bearing *br_start;
	uint8_t *code_start;
	uint8_t *sc_ret;
};

struct ezinj_ctx {
	pid_t target;
	ez_addr libc;
	ez_addr syscall_insn;
	ez_addr libc_syscall;
	ez_addr libc_dlopen;
	ez_addr actual_dlopen;
#ifdef HAVE_DL_LOAD_SHARED_LIBRARY
	ez_addr uclibc_sym_tables;
	ez_addr uclibc_loaded_modules;
	ez_addr uclibc_mips_got_reloc;
	ez_addr uclibc_dl_fixup;
	off_t dlopen_offset;
#endif
	ez_addr libc_clone;
	int shm_id;
	int sem_id;
	void *mapped_mem;
};

struct ezinj_str {
	int len;
	char *str;
};

typedef void (*pfnRegSet)(
	struct user *oregs,
	struct user *regs,
	void *pUserData
);

struct sc_req {
	uintptr_t nr;
	uintptr_t arg1;
	uintptr_t arg2;
	uintptr_t arg3;
	uintptr_t arg4;
};

struct callstack_req {
	uintptr_t stack_addr;
};

struct call_req {
	uintptr_t insn_addr;
	union {
		struct sc_req syscall;
		struct callstack_req call;
	} u;
};

#endif