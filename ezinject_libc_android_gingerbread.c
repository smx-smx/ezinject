#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include "ezinject.h"
#include "log.h"
#include "util.h"

int resolve_libc_symbols(struct ezinj_ctx *ctx){
	/**
	 * libdl.so is a fake library
	 * calling dlsym() on it will give back functions inside the linker
	 **/
	void *libdl = dlopen(DL_LIBRARY_NAME, RTLD_LAZY);
	if(!libdl){
		ERR("dlopen("DL_LIBRARY_NAME") failed: %s", dlerror());
		return 1;
	}

	ez_addr linker = {
		.local  = (uintptr_t) get_base(getpid(), DYN_LINKER_NAME, NULL),
		.remote = (uintptr_t) get_base(ctx->target, DYN_LINKER_NAME, NULL)
	};
	DBGPTR(linker.local);
	DBGPTR(linker.remote);

	ez_addr linker_dlopen = sym_addr(libdl, "dlopen", linker);
	ez_addr linker_dlclose = sym_addr(libdl, "dlclose", linker);
	ez_addr linker_dlsym = sym_addr(libdl, "dlsym", linker);
	
	DBGPTR(linker_dlopen.local);
	DBGPTR(linker_dlopen.remote);
	
	// the real libdl is the linker (which holds the implementation of dl* symbols)
	ctx->libdl = linker;
	ctx->libc_dlopen = linker_dlopen;

	ctx->dlopen_offset = PTRDIFF(linker_dlopen.local, linker.local);
	ctx->dlclose_offset = PTRDIFF(linker_dlclose.local, linker.local);
	ctx->dlsym_offset = PTRDIFF(linker_dlsym.local, linker.local);

	dlclose(libdl);
	return 0;
}