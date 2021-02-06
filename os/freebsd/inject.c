#include "config.h"

#include <sys/syscall.h>

#ifdef EZ_TARGET_FREEBSD
#include <sys/sysproto.h>
#endif

#include <sys/mman.h>

#include "ezinject.h"
#include "log.h"

uintptr_t remote_pl_alloc(struct ezinj_ctx *ctx, size_t mapping_size){
	uintptr_t result = RSCALL6(ctx, SYS_mmap,
		NULL, mapping_size,
		PROT_READ | PROT_WRITE | PROT_EXEC,
		MAP_ANONYMOUS, -1, 0
	);
	if(result == (uintptr_t)MAP_FAILED){
		return 0;
	}
	return result;
}

EZAPI remote_pl_free(struct ezinj_ctx *ctx, uintptr_t remote_shmaddr){
	struct injcode_bearing *br = (struct injcode_bearing *)ctx->mapped_mem.local;
	return (intptr_t) CHECK(RSCALL2(ctx, SYS_munmap, ctx->mapped_mem.remote, br->mapping_size));
}
