#ifndef __EZINJECT_CTX_PLATFORM_LINUX_H
#define __EZINJECT_CTX_PLATFORM_LINUX_H

struct ctx_platform {
	// holds the overwritten ELF header
	uint8_t *saved_sc_data;
	ssize_t saved_sc_size;
	int force_mmap_syscall;
	ez_addr libc_mmap;
	ez_addr libc_open;
	ez_addr libc_read;
#ifdef HAVE_DL_LOAD_SHARED_LIBRARY
	ez_addr uclibc_sym_tables;
	ez_addr uclibc_loaded_modules;
	ez_addr uclibc_mips_got_reloc;
	ez_addr uclibc_dl_fixup;
#endif
};

#endif
