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
#include "ezinject_util.h"

// android 10
#include "elfparse.h"

int resolve_libc_symbols_android10(struct ezinj_ctx *ctx){
	ez_addr linker = {
		.local  = (uintptr_t) get_base(getpid(), DYN_LINKER_NAME, NULL),
		.remote = (uintptr_t) get_base(ctx->target, DYN_LINKER_NAME, NULL)
	};
	DBGPTR(linker.local);
	DBGPTR(linker.remote);
	if(!linker.local || !linker.remote){
		ERR("Cannot find linker " DYN_LINKER_NAME);
		return -1;
	}

	void *elfh_linker = elfparse_createhandle(DYN_LINKER_NAME);
	if(elfh_linker == NULL){
		ERR("Failed to open "DYN_LINKER_NAME);
		return -1;
	}

	void *loader_dlopen = NULL;
	void *loader_dlclose = NULL;
	void *loader_dlsym = NULL;
	
	do {
		loader_dlopen = elfparse_getfuncaddr(elfh_linker, "__loader_dlopen");
		loader_dlclose = elfparse_getfuncaddr(elfh_linker, "__loader_dlclose");
		loader_dlsym = elfparse_getfuncaddr(elfh_linker, "__loader_dlsym");
	} while(0);
	elfparse_destroyhandle(elfh_linker);

	if(!loader_dlopen || !loader_dlclose || !loader_dlsym){
		ERR("Failed to find symbols");
		return -1;
	}

	ctx->dlopen_offset = (ptrdiff_t)loader_dlopen;
	ctx->dlclose_offset = (ptrdiff_t)loader_dlclose;
	ctx->dlsym_offset = (ptrdiff_t)loader_dlsym;

	ez_addr dlopen_addr = {
		.local = PTRADD(linker.local, ctx->dlopen_offset),
		.remote = PTRADD(linker.remote, ctx->dlopen_offset)
	};
	DBGPTR(dlopen_addr.local);
	DBGPTR(dlopen_addr.remote);

	// the real libdl is the linker (which holds the implementation of dl* symbols)
	ctx->libdl = linker;
	ctx->libc_dlopen = dlopen_addr;

	DBG("dlopen_offset: 0x%x", ctx->dlopen_offset);
	DBG("dlclose_offset: 0x%x", ctx->dlclose_offset);
	DBG("dlsym_offset: 0x%x", ctx->dlsym_offset);
	return 0;
}

int resolve_libc_symbols(struct ezinj_ctx *ctx){
	INFO("Trying new (Android 10) method");
	if(resolve_libc_symbols_android10(ctx) == 0){
		return 0;
	}
	INFO("Trying previous method");

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
	if(!linker.local || !linker.remote){
		ERR("Cannot find linker " DYN_LINKER_NAME);
		return -1;
	}

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