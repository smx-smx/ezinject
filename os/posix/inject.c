#include <stdlib.h>

#include "config.h"
#include "ezinject.h"
#include "log.h"
#include "ezinject_util.h"

ez_region region_sc_code = {
	.start = (void *)&__start_syscall,
	.end = (void *)&__stop_syscall
};

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


	off_t trampoline_offset = 0;
	size_t trampoline_size = ROUND_UP(
		PTRDIFF(&trampoline_exit, &trampoline),
		sizeof(uintptr_t)
	);

	off_t sc_offset = trampoline_offset + trampoline_size;
	size_t sc_size = ROUND_UP(
		REGION_LENGTH(region_sc_code),
		sizeof(uintptr_t)
	);

	size_t dataLength = sc_size + trampoline_size;
	ctx->saved_sc_data = calloc(dataLength, 1);
	ctx->saved_sc_size = dataLength;
	
	if(remote_read(ctx, ctx->saved_sc_data, codeBase, dataLength) != dataLength){
		ERR("failed to backup ELF header");
		return -1;
	}

	uint8_t *payload = calloc(1, dataLength);
	memcpy(
		payload + trampoline_offset,
		&trampoline,
		PTRDIFF(&trampoline_exit, &trampoline)
	);
	memcpy(
		payload + sc_offset,
		region_sc_code.start,
		REGION_LENGTH(region_sc_code)
	);
	DBG("dataLength: %zu", dataLength);

	intptr_t rc = -1;
	do {
		if(remote_write(ctx, codeBase, payload, dataLength) != dataLength){
			PERROR("failed to replace ELF header");
			break;
		}
		rc = 0;
	} while(0);
	free(payload);

	if(rc < 0){
		return rc;
	}


	ctx->trampoline_insn.remote = codeBase
		+ trampoline_offset
		+ PTRDIFF(&trampoline_entry, &trampoline);
	ctx->syscall_insn.remote = codeBase + sc_offset;
	DBGPTR(ctx->syscall_insn.remote);
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
