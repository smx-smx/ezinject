#include "config.h"

#if defined(EZ_TARGET_LINUX) && !defined(HAVE_SHM_SYSCALLS)
#include <asm-generic/ipc.h>
#endif

#include <sys/shm.h>
#include <sys/syscall.h>


#include "ezinject.h"
#include "ezinject_compat.h"

#include "log.h"

static uintptr_t _remote_shmat(struct ezinj_ctx *ctx, key_t shm_id, void *shmaddr, int shmflg){
	uintptr_t remote_shm_ptr = (uintptr_t)MAP_FAILED;
#ifdef HAVE_SHM_SYSCALLS
	remote_shm_ptr = CHECK(RSCALL3(ctx, __NR_shmat, shm_id, shmaddr, shmflg));
#else
	CHECK(RSCALL3(ctx, __NR_mprotect, ctx->target_codebase, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC));
	/**
	 * Calling convention for shmat in sys_ipc()
	 * arg0 - IPCCALL(0, SHMAT)    specifies version 0 of the call format (1 is apparently "iBCS2 emulator")
	 * arg1 - shmat: id
	 * arg2 - shmat: flags
	 * arg3 - pointer to memory that will hold the resulting shmaddr
	 * arg4 [VIA STACK] - shmat: shmaddr (we want this to be 0 to let the kernel pick a free region)
	 *
	 * Return: 0 on success, nonzero on error
	 * Stack layout: arguments start from offset 16 on Mips O32
	 *
	 * We pass shmaddr as arg3 aswell, so that 0 is used as shmaddr and is replaced with the new addr
	 **/
	CHECK(RSCALL4(ctx, __NR_ipc, IPCCALL(0, SHMAT), shm_id, shmflg, ctx->target_codebase + 4));
	remote_shm_ptr = ptrace(PTRACE_PEEKTEXT, ctx->target, ctx->target_codebase + 4);
	inj_dbgptr(remote_shm_ptr);
	CHECK(RSCALL3(ctx, __NR_mprotect, ctx->target_codebase, getpagesize(), PROT_READ | PROT_EXEC));
#endif
	return remote_shm_ptr;
}

uintptr_t remote_pl_alloc(struct ezinj_ctx *ctx, size_t mapping_size){
	uintptr_t result = _remote_shmat(ctx, ctx->shm_id, NULL, SHM_EXEC);
	if(result == (uintptr_t)MAP_FAILED){
		return 0;
	}
	return result;
}

EZAPI remote_pl_free(struct ezinj_ctx *ctx, uintptr_t remote_shmaddr){
	int result = -1;
	#ifdef HAVE_SHM_SYSCALLS
		result = (int) CHECK(RSCALL1(ctx, __NR_shmdt, remote_shmaddr));
	#else
		// skip syscall instruction and apply stack offset (see note about sys_ipc)
		ctx->syscall_stack.remote = ctx->target_codebase + 4 - 16;
		result = (int) CHECK(RSCALL4(ctx, __NR_ipc, IPCCALL(0, SHMDT), 0, 0, ctx->target_codebase + 4));
	#endif
	return result;
}