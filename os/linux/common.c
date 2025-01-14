/*
 * Copyright (C) 2025 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include "ezinject.h"
#include "log.h"
#include "common.h"

EZAPI linux_resolve_libc_symbols_generic(struct ezinj_ctx *ctx){
	void *h_libc = dlopen(C_LIBRARY_NAME, RTLD_LAZY);
	if(!h_libc){
		ERR("dlopen("C_LIBRARY_NAME") failed: %s", dlerror());
		return 1;
	}

	ez_addr libc_dlopen = sym_addr(h_libc, "dlopen", ctx->libc);
	ez_addr libc_dlclose = sym_addr(h_libc, "dlclose", ctx->libc);
	ez_addr libc_dlsym = sym_addr(h_libc, "dlsym", ctx->libc);
	if(!libc_dlopen.local || !libc_dlclose.local || !libc_dlsym.local){
		ERR("cannot resolve dl symbols");
		dlclose(h_libc);
		return 1;
	}

	ctx->libdl = ctx->libc;
	ctx->libc_dlopen = libc_dlopen;

	ctx->dlopen_offset = PTRDIFF(libc_dlopen.local, ctx->libc.local);
	ctx->dlclose_offset = PTRDIFF(libc_dlclose.local, ctx->libc.local);
	ctx->dlsym_offset = PTRDIFF(libc_dlsym.local, ctx->libc.local);

	dlclose(h_libc);
	return 0;
}