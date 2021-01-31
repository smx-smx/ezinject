#include <stdlib.h>

#include "config.h"
#include "ezinject.h"
#include "log.h"
#include "ezinject_util.h"

extern ez_region region_sc_insn;

#ifdef EZ_TARGET_DARWIN
EZAPI remote_sc_alloc(struct ezinj_ctx *ctx){ return 0; }
EZAPI remote_sc_free(struct ezinj_ctx *ctx){ return 0; }
#else
EZAPI remote_sc_alloc(struct ezinj_ctx *ctx){
	uintptr_t codeBase = (uintptr_t) get_base(ctx->target, NULL, NULL);
	if(codeBase == 0){
		ERR("Could not obtain code base");
		return -1;
	}
	DBGPTR(codeBase);
	ctx->target_codebase = codeBase;

	size_t dataLength = ROUND_UP(
		REGION_LENGTH(region_sc_insn),
		sizeof(uintptr_t)
	);

	ctx->saved_sc_data = calloc(dataLength, 1);
	ctx->saved_sc_size = dataLength;

	//backup and replace ELF header
	remote_read(ctx, ctx->saved_sc_data, codeBase, dataLength);
	if(remote_write(ctx, codeBase, region_sc_insn.start, dataLength) != dataLength){
		PERROR("remote_write failed");
		return -1;
	}
	ctx->syscall_insn.remote = codeBase;

#ifdef EZ_ARCH_MIPS
	// skip syscall instruction and apply stack offset (see note about sys_ipc)
	ctx->syscall_stack.remote = codeBase + 4 - 16;
#endif

	return 0;
}

EZAPI remote_sc_free(struct ezinj_ctx *ctx){
	if(remote_write(ctx, ctx->target_codebase, ctx->saved_sc_data, ctx->saved_sc_size) != ctx->saved_sc_size){
		PERROR("remote_write failed");
		return -1;
	}
	if(ctx->saved_sc_data != NULL){
		free(ctx->saved_sc_data);
		ctx->saved_sc_data = NULL;
	}
	return 0;
}
#endif
