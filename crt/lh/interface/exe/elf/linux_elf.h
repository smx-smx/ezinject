#ifndef __INTERFACE_LINUX_ELF_H
#define __INTERFACE_LINUX_ELF_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <elf.h>

enum {
	HOTPATCH_LIB_LD = 0,
	HOTPATCH_LIB_C,
	HOTPATCH_LIB_DL,
	HOTPATCH_LIB_PTHREAD,
	HOTPATCH_LIB_JUSTLOADED,
	HOTPATCH_LIB_MAX
};

enum {
	HOTPATCH_SYMBOL_IS_UNKNOWN,
	HOTPATCH_SYMBOL_IS_FUNCTION,
	HOTPATCH_SYMBOL_IS_FILENAME,
	HOTPATCH_SYMBOL_IS_SECTION,
	HOTPATCH_SYMBOL_IS_OBJECT
};

enum elf_bit {
	HOTPATCH_EXE_IS_NEITHER,
	HOTPATCH_EXE_IS_32BIT,
	HOTPATCH_EXE_IS_64BIT
};

struct elf_symbol {
	char *name;					/* null terminated symbol name */
	uintptr_t address;			/* address at which it is available */
	int type;					/* type of symbol */
	size_t size;				/* size of the symbol if available */
};

struct elf_interp {
	char *name;
	size_t length;
	uintptr_t ph_addr;
};

struct ld_procmaps {
	uintptr_t addr_begin;
	uintptr_t addr_end;
	bool addr_valid;
	int permissions;
	off_t offset;
	int device_major;
	int device_minor;
	ino_t inode;
	char *pathname;
	size_t pathname_sz;
	int filetype;
	uintptr_t mmap;
	uintptr_t mmap_begin;
	uintptr_t mmap_end;
};

struct elf_symbol *exe_load_symbols(const char *filename, size_t * sym_count, uintptr_t * entry_point, struct elf_interp *interp, enum elf_bit *is64);
struct ld_procmaps *ld_load_maps(pid_t pid, size_t * num);
void ld_free_maps(struct ld_procmaps *, size_t num);
/* the full path of the library needs to be given. */
int ld_find_library(struct ld_procmaps *, const size_t num, const char *libpath, bool inode_match, struct ld_procmaps **lib);
/* finds the address of the symbol in the library if it exists */
uintptr_t ld_find_address(const struct ld_procmaps *lib, const char *symbol, size_t * size);
uintptr_t ld_symbols_get_addr(const struct elf_symbol *syms, size_t syms_num, uintptr_t addr_begin,
								const char *symbol, size_t *size);
int elf_symbol_cmpqsort(const void *p1, const void *p2);
void ld_free_symbols(struct elf_symbol *syms, size_t syms_num);
#endif
