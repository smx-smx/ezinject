#include "ezinject_injcode.h"

INLINE void *inj_get_libdl(struct injcode_ctx *ctx){
	struct injcode_bearing *br = ctx->br;

    char *libdl_name = STR_DATA(BR_STRTBL(br));

	struct elf_resolve_hdr *tpnt;

	struct dyn_elf *rpnt;
	for (rpnt = *(br->uclibc_sym_tables); rpnt && rpnt->next; rpnt = rpnt->next){
		continue;
	}

	tpnt = br->libc_dlopen(0, &rpnt, NULL, libdl_name, 0);
	if(tpnt == NULL){
		inj_dchar(br, '!');
		return NULL;
	}

#ifdef EZ_ARCH_MIPS
	br->uclibc_mips_got_reloc(tpnt, 0);
#endif

#ifndef UCLIBC_OLD
#define GDB_SHARED_SIZE (5 * sizeof(void *))
#define SYMBOL_SCOPE_OFFSET (10 * sizeof(void *))
	struct r_scope_elem *global_scope = (struct r_scope_elem *)(
		(uintptr_t)*(br->uclibc_loaded_modules) + GDB_SHARED_SIZE +
		SYMBOL_SCOPE_OFFSET
	);
#endif

	struct dyn_elf dyn;
	inj_memset(&dyn, 0x00, sizeof(dyn));
	dyn.dyn = tpnt;

	/**
	  * FIXME: we are not handling init/fini arrays
 	  * This means the call will likely warn about 'dl_cleanup' being unresolved, but it will work anyways.
 	  * -- symbol 'dl_cleanup': can't resolve symbol
 	  */
#ifdef UCLIBC_OLD
	br->uclibc_dl_fixup(&dyn, RTLD_NOW);
#else
	br->uclibc_dl_fixup(&dyn, global_scope, RTLD_NOW);
#endif

	return (void *)tpnt->loadaddr;
}