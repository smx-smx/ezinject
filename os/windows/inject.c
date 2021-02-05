#include "ezinject.h"

uintptr_t remote_pl_alloc(struct ezinj_ctx *ctx, size_t mapping_size){
	return (uintptr_t)VirtualAllocEx(
		ctx->hProc, NULL,
		mapping_size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
}

EZAPI remote_pl_free(struct ezinj_ctx *ctx, uintptr_t remote_shmaddr){
	UNUSED(ctx);
	UNUSED(remote_shmaddr);
	return 0;
}

EZAPI remote_sc_alloc(struct ezinj_ctx *ctx){ return 0; }
EZAPI remote_sc_free(struct ezinj_ctx *ctx){ return 0; }
EZAPI remote_call_prepare(struct ezinj_ctx *ctx, struct injcode_call *call){ return 0; }