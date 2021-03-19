#include <dlfcn.h>
#include <unistd.h>
#include "ezinject.h"
#include "log.h"
#include "ezinject_util.h"

int resolve_libc_symbols(struct ezinj_ctx *ctx){
	void *h_self = dlopen(NULL, RTLD_LAZY);
	if(!h_self){
		ERR("dlopen("DYN_LINKER_NAME") failed: %s", dlerror());
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