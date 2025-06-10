/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include "ezinject_injcode.h"

#ifndef UCLIBC_OLD
#define MAX_SCAN_LIMIT 25

#define SIGN_MASK(x) (((intptr_t)(x)) >> ((sizeof(intptr_t) * 8) - 1))
#define ABS(x) (((intptr_t)(x) + SIGN_MASK(x)) ^ SIGN_MASK(x))

INLINE unsigned _get_global_scope_offset(struct injcode_ctx *ctx){
	struct injcode_bearing *br = ctx->br;
	struct elf_resolve_hdr *elf_tpnt = *(br->uclibc_loaded_modules);

#define IS_PTR(x) ( ((x) != 0) && ABS(PTRDIFF(x, elf_tpnt)) < 0x1000 )
// if we are still in pointer range after subtracting, not a pointer (small enough value)
#define IS_NOT_PTR(x) IS_PTR(PTRDIFF(elf_tpnt, x))

	PCALL(ctx, inj_dbgptr, elf_tpnt);
	uintptr_t *pdw = (uintptr_t *)elf_tpnt;
	for(int i=0; i<MAX_SCAN_LIMIT - 3; i++){
		if(1
		&& pdw[i+0] == 1 //libtype == elf_executable
		&& IS_PTR(pdw[i+1]) //symbol_scope.r_list
		&& IS_NOT_PTR(pdw[i+2]) && pdw[i+2] > 0 //symbol_scope.n_list
		&& *(uintptr_t *)(pdw[i+1]) == UPTR(elf_tpnt) //symbol_scope.r_list[0] == elf_tpnt
		){
			off_t offset = (i + 1) * sizeof(uintptr_t);
			return offset;
		}
	}

	return 0;

#undef IS_PTR
#undef IS_NOT_PTR
}
#endif

INLINE void *inj_get_libdl(struct injcode_ctx *ctx){
	struct injcode_bearing *br = ctx->br;

    const char *libdl_name = BR_STRTBL(br)[EZSTR_API_LIBDL].str;

	struct elf_resolve_hdr *tpnt;

	/** adapted from ldso/libdl/libdl.c, do_dlopen **/

	// get to the last symbol chain
	struct dyn_elf *rpnt;
	for (rpnt = *(br->uclibc_sym_tables); rpnt && rpnt->next; rpnt = rpnt->next){
		continue;
	}

	// calls _dl_load_shared_library, will insert tpnt into rpnt->next
	tpnt = CALL_FPTR(br->libc_dlopen,
		0, &rpnt, NULL, libdl_name, 0);
	if(tpnt == NULL){
		PCALL(ctx, inj_dchar, '!');
		return NULL;
	}

#ifdef EZ_ARCH_MIPS
	CALL_FPTR(br->uclibc_mips_got_reloc,
		tpnt, 0);
#endif

#ifndef UCLIBC_OLD
	/**
	 * we would normally need to build a local symbol scope
	 * however, since we're in libdl scope, we will steal the global one
	 **/

	// use an heuristic to locate the symbol scope offset in tpnt
	unsigned scope_offset = _get_global_scope_offset(ctx);
	if(scope_offset == 0){
		PCALL(ctx, inj_dchar, '!');
		return NULL;
	}

	struct elf_resolve_hdr *elf_tpnt = *(br->uclibc_loaded_modules);
	struct r_scope_elem *global_scope = (struct r_scope_elem *)(PTRADD(elf_tpnt, scope_offset));
	PCALL(ctx, inj_dbgptr, global_scope);

#endif

	struct dyn_elf dyn;
	PCALL(ctx, inj_memset, &dyn, 0x00, sizeof(dyn));
	dyn.dyn = tpnt;

	/**
	  * FIXME: we are not handling init/fini arrays
 	  * This means the call will likely warn about 'dl_cleanup' being unresolved, but it will work anyways.
 	  * -- symbol 'dl_cleanup': can't resolve symbol
 	  */
#ifdef UCLIBC_OLD
	CALL_FPTR(br->uclibc_dl_fixup,
		&dyn, RTLD_NOW);
#else
	CALL_FPTR(br->uclibc_dl_fixup,
		&dyn, global_scope, RTLD_NOW);
#endif

	return (void *)tpnt->loadaddr;
}
