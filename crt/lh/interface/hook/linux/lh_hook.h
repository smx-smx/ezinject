#ifndef __LH_HOOK_H
#define __LH_HOOK_H

#include <stdint.h>
#include "interface/exe/elf/linux_elf.h"

#define LHM_MAX_FN_HOOKS 32
#define LHM_STR_LENGTH 64
#define LHM_FN_COPY_BYTES 16


enum lh_hook_kind {
	LHM_FN_HOOK_TRAILING = 0,
	LHM_FN_HOOK_BY_NAME,
	LHM_FN_HOOK_BY_OFFSET,
	LHM_FN_HOOK_BY_AOBSCAN
};

typedef struct {
	enum elf_bit is64;
	struct elf_symbol *exe_symbols;
	size_t exe_symbols_num;
	uintptr_t exe_entry_point;
	struct elf_interp exe_interp;	/* dynamic loader from .interp in the exe */
	struct ld_procmaps *ld_maps;
	size_t ld_maps_num;
} lh_session_t;

/*
 * Function hook definition
 */
typedef struct {
	enum lh_hook_kind hook_kind;
	char libname[LHM_STR_LENGTH];
	char symname[LHM_STR_LENGTH];
	// or offset to codesegment
	uintptr_t sym_offset;
	uintptr_t hook_fn;
	uintptr_t orig_function_ptr;
	uintptr_t code_rest_ptr;
	size_t opcode_bytes_to_restore;
	size_t aob_size;
	unsigned char *aob_pattern;
} lh_fn_hook_t;

/*
 * Module definition
 */
typedef struct {
	int version;
	int hook_mode;
	lh_fn_hook_t fn_hooks[LHM_MAX_FN_HOOKS];
} lh_hook_t;

#endif