#include "config.h"

#if defined(EZ_TARGET_LINUX) && !defined(HAVE_SHM_SYSCALLS)
#include <asm-generic/ipc.h>
#endif

#include <sys/shm.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ptrace.h>


#include "ezinject.h"
#include "ezinject_compat.h"

#include "log.h"

#ifndef HAVE_SHM_SYSCALLS
static EZAPI _rcall_handler_pre(struct ezinj_ctx *ctx, struct injcode_call *rcall){
	if(rcall->argv[0] != __NR_ipc || rcall->argv[1] != IPCCALL(0, SHMAT)){
		return 0;
	}
	//syscall(__NR_ipc, IPCCALL, id, flags, memptr, shmaddr)
	//            0        1      2    3      4       5
	rcall->argv[4] = RCALL_FIELD_ADDR(rcall, result2);
	DBG("result2: %p", (void *)rcall->argv[4]);
	return 0;
}

static EZAPI _rcall_handler_post(struct ezinj_ctx *ctx, struct injcode_call *rcall){
	if(rcall->argv[0] != __NR_ipc || rcall->argv[1] != IPCCALL(0, SHMAT)){
		return 0;
	}
	
	DBG("sys_ipc(SHMAT) returned %d", (int)rcall->result);
	// call succeded, copy result2 over result
	if(rcall->result == 0){
		DBG("overwriting shmat return");
		uintptr_t result = 0;
		remote_read(ctx, &result, RCALL_FIELD_ADDR(rcall, result2), sizeof(uintptr_t));
		DBGPTR((void *)result);
		remote_write(ctx, RCALL_FIELD_ADDR(rcall, result), &result, sizeof(uintptr_t));
	}
	return 0;
}
static void _install_handlers(struct ezinj_ctx *ctx){
	ctx->rcall_handler_pre = _rcall_handler_pre;
	ctx->rcall_handler_post = _rcall_handler_post;
}
#else
static void _install_handlers(struct ezinj_ctx *ctx){
	UNUSED(ctx);
}
#endif

static uintptr_t _remote_shmat(struct ezinj_ctx *ctx, key_t shm_id, void *shmaddr, int shmflg){
	uintptr_t remote_shm_ptr = (uintptr_t)MAP_FAILED;
#ifdef HAVE_SHM_SYSCALLS
	remote_shm_ptr = CHECK(RSCALL3(ctx, __NR_shmat, shm_id, shmaddr, shmflg));
#else
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
	remote_shm_ptr = CHECK(RSCALL6(ctx, __NR_ipc, IPCCALL(0, SHMAT), shm_id, shmflg, 0, 0, 0));
#endif
	return remote_shm_ptr;
}

uintptr_t remote_pl_alloc(struct ezinj_ctx *ctx, size_t mapping_size){
	uintptr_t result = 0;
	_install_handlers(ctx);
	do {
		result = _remote_shmat(ctx, ctx->shm_id, NULL, SHM_EXEC);
		if(result == (uintptr_t)MAP_FAILED){
			result = 0;
			break;
		}
	} while(0);
	return result;
}

EZAPI remote_pl_free(struct ezinj_ctx *ctx, uintptr_t remote_shmaddr){
	int result = -1;
	#ifdef HAVE_SHM_SYSCALLS
		result = (int) CHECK(RSCALL1(ctx, __NR_shmdt, remote_shmaddr));
	#else
		_install_handlers(ctx);
		result = (int) CHECK(RSCALL6(ctx, __NR_ipc, IPCCALL(0, SHMDT), 0, 0, 0, remote_shmaddr, 0));
	#endif
	return result;
}

EZAPI remote_sc_check(struct ezinj_ctx *ctx){
	pid_t remote_pid = (pid_t)RSCALL0(ctx, __NR_getpid);
	if(remote_pid != ctx->target){
		ERR("Remote syscall returned incorrect result!");
		ERR("Expected: %u, actual: %u", ctx->target, remote_pid);
		return -1;
	}
	return 0;
}