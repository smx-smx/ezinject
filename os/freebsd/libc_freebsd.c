/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <dlfcn.h>
#include <unistd.h>
#include "ezinject.h"
#include "log.h"
#include "ezinject_util.h"

EZAPI resolve_libc_symbols(struct ezinj_ctx *ctx){
	void *h_self = dlopen(NULL, RTLD_LAZY);
	if(!h_self){
		ERR("dlopen(%s) failed: %s", ctx->ldso_name, dlerror());
		return 1;
	}

	ez_addr linker = {
		.local  = (uintptr_t) get_base(ctx, getpid(), ctx->ldso_name, NULL),
		.remote = (uintptr_t) get_base(ctx, ctx->target, ctx->ldso_name, NULL)
	};
	DBGPTR(linker.local);
	DBGPTR(linker.remote);
	if(!linker.local || !linker.remote){
		ERR("Cannot find linker %s" ctx->ldso_name);
		return -1;
	}

	ez_addr linker_dlopen = sym_addr(h_self, "dlopen", linker);
	ez_addr linker_dlclose = sym_addr(h_self, "dlclose", linker);
	ez_addr linker_dlsym = sym_addr(h_self, "dlsym", linker);
	if(!linker_dlopen.local || !linker_dlclose.local || !linker_dlsym.local){
		ERR("Cannot resolve dl symbols");
		dlclose(h_self);
		return 1;
	}

	// the real libdl is the linker (which holds the implementation of dl* symbols)
	ctx->libdl = linker;
	ctx->libc_dlopen = linker_dlopen;

	ctx->dlopen_offset = PTRDIFF(linker_dlopen.local, linker.local);
	ctx->dlclose_offset = PTRDIFF(linker_dlclose.local, linker.local);
	ctx->dlsym_offset = PTRDIFF(linker_dlsym.local, linker.local);

	dlclose(h_self);
	return 0;
}
