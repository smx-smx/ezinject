/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
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

EZAPI resolve_libc_symbols(struct ezinj_ctx *ctx){
	void *h_libc = dlopen(C_LIBRARY_NAME, RTLD_LAZY);
	if(!h_libc){
		ERR("dlopen("C_LIBRARY_NAME") failed: %s", dlerror());
		return 1;
	}

	ez_addr libc_dlopen;
	do {
		libc_dlopen = sym_addr(h_libc, "__libc_dlopen_mode", ctx->libc);
		if(libc_dlopen.remote != 0){
			break;
		}
		INFO("__libc_dlopen_mode not found, trying glibc >= 2.34 method");
		libc_dlopen = sym_addr(h_libc, "_dl_open", ctx->libc);
		if(libc_dlopen.remote != 0){
			break;
		}
		INFO("_dl_open not found, trying generic method");
		if(!linux_resolve_libc_symbols_generic(ctx)){
			// success
			return 0;
		}
		ERR("failed to resolve glibc symbols");
		return 1;
	} while(0);

	if(!libc_dlopen.remote){
		ERR("failed to resolve glibc internal dlopen");
		dlclose(h_libc);
		return 1;
	}

	ctx->libc_dlopen = libc_dlopen;

	/**
	 * old glibc on ARM OABI uses __NR_syscall like this:
	 *  result = syscall(__NR_syscall, a1, a2, a3);
	 * where
	 * 	a1: syscall number
	 *  a2: arg1
	 *  a3: arg2
	 * this means we can only do syscalls with 2 arguments,
	 * making __NR_close the only usable syscall.
	 * for others, we must resolve the respective libc symbols
	 */
	ez_addr libc_mmap = sym_addr(h_libc, "mmap", ctx->libc);
	ez_addr libc_open = sym_addr(h_libc, "open", ctx->libc);
	ez_addr libc_read = sym_addr(h_libc, "read", ctx->libc);

	ctx->libc_mmap = libc_mmap;
	ctx->libc_open = libc_open;
	ctx->libc_read = libc_read;

	DBGPTR(ctx->libc_mmap.remote);
	DBGPTR(ctx->libc_open.remote);
	DBGPTR(ctx->libc_read.remote);

	dlclose(h_libc);
	return 0;
}
