#ifndef __EZINJECT_INJCODE_H
#define __EZINJECT_INJCODE_H

#include <sys/types.h>
#include <linux/limits.h>
#include <pthread.h>
#include <sys/sem.h>


#include "config.h"

#define EZ_SEM_LIBCTL 0

#define SIZEOF_BR(br) (sizeof(br) + (br).dyn_size)

// temporary stack size
#define PL_STACK_SIZE 64 * 1024

#define INJ_PATH_MAX 128

#define EMIT_LABEL(name) \
	asm volatile( \
		".globl "name"\n" \
		name":\n" \
	)


#define UNUSED(x) (void)(x)
#define UPTR(x) ((uintptr_t)(x))

#define STRSZ(x) (strlen(x) + 1)
#define ALIGNMSK(y) ((y)-1)
#define ALIGN(x, y) ((void *)((UPTR(x) + ALIGNMSK(y)) & ~ALIGNMSK(y)))

#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

#define WORDALIGN(x) ALIGN(x, sizeof(void *))

#define PAGEALIGN(x)  ALIGN(x, getpagesize())
#define PTRADD(a, b) ( UPTR(a) + UPTR(b) )
#define PTRDIFF(a, b) ( UPTR(a) - UPTR(b) )



#define INLINE static inline __attribute__((always_inline))

#ifdef HAVE_DL_LOAD_SHARED_LIBRARY
#include <elf.h>

#define ElfW(type)	_ElfW (Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e,w,t)	_ElfW_1 (e, w, _##t)
#define _ElfW_1(e,w,t)	e##w##t
#define DL_LOADADDR_TYPE ElfW(Addr)
#include <link.h>		/* Defines __ELF_NATIVE_CLASS.  */

#ifndef UCLIBC_OLD
struct r_scope_elem {
	void **r_list; /* Array of maps for the scope.  */
	unsigned int r_nlist;        /* Number of entries in the scope.  */
	void *next;
};
#endif

struct init_fini {
    void **init_fini;
    unsigned long nlist; /* Number of entries in init_fini */
};

struct dyn_elf {
  void * dyn;
  void * next_handle;  /* Used by dlopen et al. */
  struct init_fini init_fini;
  void * next;
  void * prev;
};

struct elf_resolve_hdr {
	/* These entries must be in this order to be compatible with the interface used
		by gdb to obtain the list of symbols. */
	DL_LOADADDR_TYPE loadaddr;	/* Base address shared object is loaded at.  */
	char *libname;		/* Absolute file name object was found in.  */
	ElfW(Dyn) *dynamic_addr;	/* Dynamic section of the shared object.  */
	struct elf_resolve_hdr *next;
	struct elf_resolve_hdr *prev;
	/* Nothing after this address is used by gdb. */
};
#endif

struct injcode_user {
	// any user data here
};

struct injcode_bearing
{
	size_t mapping_size;

	pthread_t user_tid;
	pid_t user_ft;

	void *userlib;

	// => "pthread_join"
	char sym_pthread_join[14];

#if defined(HAVE_LIBC_DLOPEN_MODE)
	void *(*libc_dlopen)(const char *name, int mode);
#elif defined(HAVE_DL_LOAD_SHARED_LIBRARY)
	void *(*libc_dlopen)(unsigned rflags, struct dyn_elf **rpnt,
		void *tpnt, char *full_libname, int trace_loaded_objects);
	struct dyn_elf **uclibc_sym_tables;
#ifdef UCLIBC_OLD
	int (*uclibc_dl_fixup)(struct dyn_elf *rpnt, int now_flag);
#else
	int (*uclibc_dl_fixup)(struct dyn_elf *rpnt, struct r_scope_elem *scope, int now_flag);
#endif
#ifdef EZ_ARCH_MIPS
	void (*uclibc_mips_got_reloc)(struct elf_resolve_hdr *tpnt, int lazy);
#endif
	struct elf_resolve_hdr **uclibc_loaded_modules;
#endif
	off_t dlopen_offset;
	off_t dlclose_offset;
	off_t dlsym_offset;
	// libdl base address, if already loaded
	void *libdl_handle;
	long (*libc_syscall)(long number, ...);
	int (*libc_semop)(int semid, struct sembuf *sops, size_t nsops);
#ifdef DEBUG
	int (*libc_puts)(const char *s);
	int (*libc_putchar)(int c);
#endif
	int (*libc_snprintf)( char * s, size_t n, const char * format, ... );
	int (*libc_putenv)(char *string);
	struct injcode_user user;
	int argc;
	int dyn_size;
	char *argv[];
};

#define PL_STACK(br) (uintptr_t *)((uintptr_t)((br) + MAPPINGSIZE))

extern void injected_clone_proper(struct injcode_bearing *br);

extern int clone_fn(void *arg);

extern void injected_sc_start();
extern void injected_sc_end();

extern void injected_clone_entry();
extern void clone_entry();

extern void injected_clone();

extern void injected_code_start();
extern void injected_code_end();

#endif
