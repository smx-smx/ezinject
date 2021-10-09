/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include "config.h"
#include <unistd.h>
#include <dlfcn.h>
#include "ezinject.h"
#include "log.h"
#include "ezinject_util.h"

int resolve_libc_symbols(struct ezinj_ctx *ctx){
	ez_addr ldso = {
		.local = (uintptr_t)get_base(getpid(), "ld-uClibc", NULL),
		.remote = (uintptr_t)get_base(ctx->target, "ld-uClibc", NULL)
	};
	if(!ldso.local || !ldso.remote){
		ERR("Failed to get ldso base");
		return 1;
	}

	void *h_ldso = dlopen(DYN_LINKER_NAME, RTLD_LAZY);
	if(!h_ldso){
		ERR("dlopen("DYN_LINKER_NAME") failed: %s", dlerror());
		return 1;
	}

	ez_addr libc_dlopen = sym_addr(h_ldso, "_dl_load_shared_library", ldso);

	ez_addr uclibc_sym_tables = sym_addr(h_ldso, "_dl_symbol_tables", ldso);
	ez_addr uclibc_loaded_modules = sym_addr(h_ldso, "_dl_loaded_modules", ldso);

#ifdef EZ_ARCH_MIPS
	ez_addr uclibc_mips_got_reloc = sym_addr(h_ldso, "_dl_perform_mips_global_got_relocations", ldso);
	ctx->uclibc_mips_got_reloc = uclibc_mips_got_reloc;
#endif

	ez_addr uclibc_dl_fixup = sym_addr(h_ldso, "_dl_fixup", ldso);
	ctx->uclibc_sym_tables = uclibc_sym_tables;
	ctx->uclibc_loaded_modules = uclibc_loaded_modules;
	ctx->uclibc_dl_fixup = uclibc_dl_fixup;
	dlclose(h_ldso);

	ctx->libc_dlopen = libc_dlopen;

	void *h_libc = dlopen(C_LIBRARY_NAME, RTLD_LAZY);
	if(!h_libc){
		ERR("dlopen("C_LIBRARY_NAME") failed: %s", dlerror());
		return 1;
	}

	ez_addr libc_mmap = sym_addr(h_libc, "mmap", ctx->libc);
	ctx->libc_mmap = libc_mmap;

	dlclose(h_libc);
	return 0;
}
