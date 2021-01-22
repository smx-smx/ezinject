#include <dlfcn.h>
#include "ezinject.h"
#include "log.h"

int resolve_libc_symbols(struct ezinj_ctx *ctx){
	void *h_libc = dlopen(C_LIBRARY_NAME, RTLD_LAZY);
	if(!h_libc){
		ERR("dlopen("C_LIBRARY_NAME") failed: %s", dlerror());
		return 1;
	}

	ez_addr libc_dlopen = sym_addr(h_libc, "dlopen", ctx->libc);
	ctx->libc_dlopen = libc_dlopen;

	dlclose(h_libc);
	return 0;
}