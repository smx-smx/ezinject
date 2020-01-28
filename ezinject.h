#ifndef __EZINJECT_H
#define __EZINJECT_H

#include "config.h"

#define UNUSED(x) (void)(x)
#define UPTR(x) ((uintptr_t)(x))


#define STRSZ(x) (strlen(x) + 1)
#define ALIGNMSK(y) ((y)-1)
#define ALIGN(x, y) ((void *)((UPTR(x) + y) & ~ALIGNMSK(y)))

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

static ez_region region_pl_code = {
	.start = (void *)&injected_code_start,
	.end = (void *)&injected_code_end
};

static ez_region region_sc_insn = {
	.start = (void *)&injected_sc_start,
	.end = (void *)&injected_sc_end
};


struct ezinj_ctx {
	pid_t target;
	ez_addr libc;
	ez_addr syscall_insn;
	ez_addr libc_clone;
	int shm_id;
	int sem_id;
	void *mapped_mem;
};

struct ezinj_str {
	int len;
	char *str;
};

#endif