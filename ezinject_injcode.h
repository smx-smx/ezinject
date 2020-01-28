#ifndef __EZINJECT_INJCODE_H
#define __EZINJECT_INJCODE_H

#include <sys/types.h>
#include <linux/limits.h>

#include "config.h"

#define MAPPINGSIZE 8192
#define STACKSIZE 1024
#define INJ_PATH_MAX 128

#ifdef HAVE_DL_LOAD_SHARED_LIBRARY
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
#endif

struct injcode_user {
	// any user data here
};

struct injcode_bearing
{
#if defined(HAVE_LIBC_DLOPEN_MODE)
	void *(*libc_dlopen)(const char *name, int mode);
#elif defined(HAVE_DL_LOAD_SHARED_LIBRARY)
	void *(*libc_dlopen)(unsigned rflags, struct dyn_elf **rpnt,
		void *tpnt, char *full_libname, int trace_loaded_objects);
	struct dyn_elf **uclibc_sym_tables;
#endif
	long (*libc_syscall)(long number, ...);
	int (*libc_clone)(
		int (*fn)(void *),
		void *stack, int flags, void *arg, ...);
	struct injcode_user user;
	int argc;
	int dyn_size;
	char *argv[];
};

extern int clone_fn(void *arg);

extern void injected_sc_start();
extern void injected_sc_end();

extern void injected_clone_entry();
extern void clone_entry();

extern void injected_clone();

extern void injected_code_start();
extern void injected_code_end();

#endif