#ifndef __EZINJECT_INJCODE_PLATFORM_LINUX_H
#define __EZINJECT_INJCODE_PLATFORM_LINUX_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#if defined(HAVE_DL_LOAD_SHARED_LIBRARY)
#include <elf.h>
#include <link.h>
struct r_scope_elem;
struct dyn_elf;
struct elf_resolve_hdr;
#endif

struct bearing_platform {
#if defined(HAVE_DL_LOAD_SHARED_LIBRARY)
	struct {
		void *(*fptr)(unsigned rflags, struct dyn_elf **rpnt,
			void *tpnt, char *full_libname, int trace_loaded_objects);
		void *got;
		void *self;
	} libc_dlopen;
	struct dyn_elf **uclibc_sym_tables;
#ifdef UCLIBC_OLD
	struct {
		int (*fptr)(struct dyn_elf *rpnt, int now_flag);
		void *got;
		void *self;
	} uclibc_dl_fixup;
#else
	struct {
		int (*fptr)(struct dyn_elf *rpnt, struct r_scope_elem *scope, int now_flag);
		void *got;
		void *self;
	} uclibc_dl_fixup;
#endif
#ifdef EZ_ARCH_MIPS
	struct {
		void (*fptr)(struct elf_resolve_hdr *tpnt, int lazy);
	} uclibc_mips_got_reloc;
#endif
	struct elf_resolve_hdr **uclibc_loaded_modules;
#elif defined(HAVE_LIBC_DLOPEN_MODE) || defined(HAVE_LIBC_DL_OPEN)
	struct {
		void *(*fptr)(const char *name, int mode);
		void *got;
		void *self;
	} libc_dlopen;
#else
	struct {
		void *(*fptr)(const char *name, int mode);
		void *got;
		void *self;
	} libc_dlopen;
#endif
	off_t pl_filename_offset;
};

struct call_platform {
	struct {
		long (*fptr)(long number, ...);
		void *got;
		void *self;
	} libc_syscall;
	struct {
		void *(*fptr)(void *addr, size_t length, int prot, int flags,
			  int fd, off_t offset);
		void *got;
		void *self;
	} libc_mmap;
	struct {
		int (*fptr)(const char *pathname, int flags, ...);
		void *got;
		void *self;
	} libc_open;
	struct {
		ssize_t (*fptr)(int fd, void *buf, size_t count);
		void *got;
		void *self;
	} libc_read;
};

#endif
