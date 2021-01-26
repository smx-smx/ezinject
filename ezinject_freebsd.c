#include "ezinject.h"

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

int remote_pl_free(struct ezinj_ctx *ctx, uintptr_t remote_shmaddr){
	return (int) CHECK(RSCALL1(ctx, SYS_shmdt, remote_shmaddr));
}