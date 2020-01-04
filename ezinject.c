#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sched.h>
#ifdef __mips
#include <linux/shm.h>
#endif
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/shm.h>
#include <sys/user.h>

#define CHECK(x) ({\
long _tmp = (x);\
DBG("%s = %lu", #x, _tmp);\
_tmp;})

#include "util.h"
#include "ezinject_injcode.h"

enum verbosity_level verbosity = V_DBG;

#if defined(__arm__)
#define REG_PC uregs[15]
#define REG_NR uregs[7]
#define REG_RET uregs[0]
#define REG_ARG1 uregs[0]
#define REG_ARG2 uregs[1]
#define REG_ARG3 uregs[2]
#define REG_ARG4 uregs[3]
#define REG_ARG5 uregs[4]
#define REG_ARG6 uregs[5]
const char SYSCALL_INSN[] = {0x00, 0x00, 0x00, 0xef}; /* swi 0 */
const char RET_INSN[] = {0x04, 0xf0, 0x9d, 0xe4}; /* pop {pc} */
#elif defined(__i386__)
#define REG_PC eip
#define REG_NR eax
#define REG_RET eax
#define REG_ARG1 ebx
#define REG_ARG2 ecx
#define REG_ARG3 edx
#define REG_ARG4 esi
#define REG_ARG5 edi
#define REG_ARG6 ebp
const char SYSCALL_INSN[] = {0xcd, 0x80}; /* int 0x80 */
const char RET_INSN[] = {0xc3}; /* ret */
#elif defined(__amd64__)
#define REG_PC rip
#define REG_NR rax
#define REG_RET rax
#define REG_ARG1 rdi
#define REG_ARG2 rsi
#define REG_ARG3 rdx
#define REG_ARG4 r10
#define REG_ARG5 r8
#define REG_ARG6 r9
const char SYSCALL_INSN[] = {0x0f, 0x05}; /* syscall */
const char RET_INSN[] = {0xc3}; /* ret */
#elif defined(__mips__)
#define REG_PC regs[EF_CP0_EPC]
#define REG_RET regs[2] //$v0
#define REG_NR regs[2] //$v0
#define REG_ARG1 regs[4] //$a0
#define REG_ARG2 regs[5] //$a1
#define REG_ARG3 regs[6] //$a2
#define REG_ARG4 regs[7] //$a3
char SYSCALL_INSN[] = {0x00, 0x00, 0x00, 0x0c}; //syscall
char RET_INSN[] = {
	0x8f, 0xbf, 0x00, 0x00, //lw $ra, 0($sp)
	0x23, 0xbd, 0x00, 0x04, //addi $sp, $sp, 4
	0x03, 0xe0, 0x00, 0x08  //jr $ra
};

#else
#error "Unsupported architecture"
#endif

#ifndef __NR_mmap
#define __NR_mmap __NR_mmap2 /* Functionally equivalent for our use case. */
#endif

#define MAPPINGSIZE 4096
#define MEMALIGN 4 /* MUST be a power of 2 */
#define ALIGNMSK ~(MEMALIGN-1)

#define ALIGN(x) ((void *)(((uintptr_t)x + MEMALIGN) & ALIGNMSK))
#define PTRDIFF(a, b) ( ((uintptr_t)(a)) - ((uintptr_t)(b)) )

#define CLONE_FLAGS (CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_PARENT|CLONE_THREAD|CLONE_IO)

typedef struct {
	uintptr_t base_remote;
	uintptr_t base_local;
} ez_addr;

#define EZ_LOCAL(ref, remote) (ref.base_local + PTRDIFF(remote, ref.base_remote))
#define EZ_REMOTE(ref, local) (ref.base_remote + PTRDIFF(local, ref.base_local))


uintptr_t remote_call(pid_t target, void *insn_addr, int nr, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
	struct user orig_ctx, new_ctx;
	memset(&orig_ctx, 0x00, sizeof(orig_ctx));

	ptrace(PTRACE_GETREGS, target, 0, &orig_ctx);
	memcpy(&new_ctx, &orig_ctx, sizeof(orig_ctx));

	new_ctx.regs.REG_PC = (uintptr_t)insn_addr;
	new_ctx.regs.REG_NR = nr;
	new_ctx.regs.REG_ARG1 = arg1;
	new_ctx.regs.REG_ARG2 = arg2;
	new_ctx.regs.REG_ARG3 = arg3;
	/*new_ctx.regs.REG_ARG4 = arg4;
	new_ctx.regs.REG_ARG5 = arg5;
	new_ctx.regs.REG_ARG6 = arg6;*/
	ptrace(PTRACE_SETREGS, target, 0, &new_ctx);

	ptrace(PTRACE_SYSCALL, target, 0, 0); /* Run until syscall entry */
	waitpid(target, 0, 0);
	ptrace(PTRACE_SYSCALL, target, 0, 0); /* Run until syscall return */
	waitpid(target, 0, 0);
	ptrace(PTRACE_GETREGS, target, 0, &new_ctx); /* Get return value */
	
	ptrace(PTRACE_SETREGS, target, 0, &orig_ctx);
	DBG("remote_call(%d) = %zu", nr, (uintptr_t)new_ctx.regs.REG_RET);

	return new_ctx.regs.REG_RET;
}

void *locate_gadget(uint8_t *base, size_t limit, uint8_t *search, size_t searchSz){
	for(size_t i = 0; i < limit; ++i)
	{
		if(!memcmp(&base[i], search, searchSz))
		{
			return (void *)&base[i];
		}
	}
	return NULL;
}

struct ezinj_ctx {
	pid_t target;
	ez_addr libc;
	ez_addr libc_syscall;
	ez_addr libc_syscall_insn;
};

struct ezinj_pl {
	uint8_t *code_start;
	uint8_t *syscall_insn;
	uint8_t *ret_insn;
	uint8_t *br_start;
};

int libc_init(struct ezinj_ctx *ctx){
	/**
	 * locate glibc in /proc/<pid>/maps
	 * both for local and remote procs
	 */
	ez_addr libc = {
		.base_local  = (uintptr_t) get_base(getpid(), "libc-"),
		.base_remote = (uintptr_t) get_base(ctx->target, "libc-")
	};

	DBGPTR(libc.base_remote);
	DBGPTR(libc.base_local);
	
	if(!libc.base_local || !libc.base_remote)
	{
		ERR("Failed to get libc base");
		return 1;
	}

	ez_addr libc_syscall = {
		.base_local  = (uintptr_t)&syscall,
		.base_remote = EZ_REMOTE(libc, &syscall)
	};

	ez_addr libc_syscall_insn = {
		.base_local = (uintptr_t)locate_gadget(
			(uint8_t *)libc_syscall.base_local, 0x1000,
			(uint8_t *)SYSCALL_INSN,
			sizeof(SYSCALL_INSN)
		),
	};
	libc_syscall_insn.base_remote = EZ_REMOTE(libc, libc_syscall_insn.base_local);

	if(!libc_syscall_insn.base_local)
	{
		ERR("Failed to find syscall instruction in libc");
		return 1;
	}
	DBGPTR(libc_syscall_insn.base_local);

	ctx->libc = libc;
	ctx->libc_syscall = libc_syscall;
	ctx->libc_syscall_insn = libc_syscall_insn;
	return 0;
}

struct injcode_bearing prepare_bearing(struct ezinj_ctx *ctx){
	/**
	 * Rebase local symbols to remote
	 */
	#define GETSYM(sym) { \
		.base_local = (uintptr_t) (sym), \
		.base_remote = (uintptr_t) EZ_REMOTE(ctx->libc, (uintptr_t)(sym)) \
	}

	ez_addr libc_dlopen_mode = GETSYM(dlsym(RTLD_DEFAULT, "__libc_dlopen_mode"));
	ez_addr libc_shmget = GETSYM(&shmget);
	ez_addr libc_shmat = GETSYM(&shmat);
	ez_addr libc_shmdt = GETSYM(&shmdt);

	struct injcode_bearing br = {
		.libc_syscall = (void *)ctx->libc_syscall.base_remote,
		.libc_dlopen_mode = (void *)libc_dlopen_mode.base_remote,
		.libc_shmget = (void *)libc_shmget.base_remote,
		.libc_shmat = (void *)libc_shmat.base_remote,
		.libc_shmdt = (void *)libc_shmdt.base_remote
	};
	return br;
}


struct ezinj_pl prepare_payload(void *mapped_mem, struct injcode_bearing br){
	size_t injected_size = (size_t)PTRDIFF(injected_code_end, injected_code);
	DBG("injsize=%zu", injected_size);

	uint8_t *code_start = (uint8_t *)mapped_mem;
	uint8_t *syscall_insn = ALIGN(code_start + injected_size);
	uint8_t *ret_insn = syscall_insn + sizeof(SYSCALL_INSN);
	uint8_t *br_start = ALIGN(ret_insn + sizeof(RET_INSN));

	memcpy(code_start, injected_code, injected_size);
	memcpy(syscall_insn, (void *)SYSCALL_INSN, sizeof(SYSCALL_INSN));
	memcpy(ret_insn, (void*)RET_INSN, sizeof(RET_INSN));
	memcpy(br_start, &br, sizeof(br));

	struct ezinj_pl pl = {
		.code_start = code_start,
		.syscall_insn = syscall_insn,
		.ret_insn = ret_insn,
		.br_start = br_start
	};
	return pl;
}

#define UPTR(x) ((uintptr_t)x)
#define __RCALL(ctx, x, ...) remote_call(ctx.target, (void *)x, __VA_ARGS__)
#define __RCALL_SC(ctx, n, ...) __RCALL(ctx, ctx.libc_syscall_insn.base_remote, n, __VA_ARGS__)

// Remote Call
#define RCALL0(ctx,x)                __RCALL(ctx,x,0,0,0,0)
#define RCALL1(ctx,x,a1)             __RCALL(ctx,x,0,UPTR(a1),0,0)
#define RCALL2(ctx,x,a1,a2)          __RCALL(ctx,x,0,UPTR(a1),UPTR(a2),0)
#define RCALL3(ctx,x,a1,a2,a3)       __RCALL(ctx,x,0,UPTR(a1),UPTR(a2),UPTR(a3))

// Remote System Call
#define RSCALL0(ctx,n)               __RCALL_SC(ctx,n,0,0,0)
#define RSCALL1(ctx,n,a1)            __RCALL_SC(ctx,n,UPTR(a1),0,0)
#define RSCALL2(ctx,n,a1,a2)         __RCALL_SC(ctx,n,UPTR(a1),UPTR(a2),0)
#define RSCALL3(ctx,n,a1,a2,a3)      __RCALL_SC(ctx,n,UPTR(a1),UPTR(a2),UPTR(a3))

int ezinject_main(struct ezinj_ctx ctx, const char *argLib, int *pshm_id){
	int shm_id;

	/* Verify that remote_call works correctly */
	pid_t remote_pid = (pid_t)RSCALL0(ctx, __NR_getpid);
	if(remote_pid != ctx.target)
	{
		ERR("Remote syscall returned incorrect result!");
		ERR("Expected: %u, actual: %u", ctx.target, remote_pid);
		return 1;
	}

	if((shm_id = shmget(ctx.target, MAPPINGSIZE, IPC_CREAT | IPC_EXCL | S_IRWXO)) < 0){
		PERROR("shmget");
		return 1;
	}

	void *mapped_mem = shmat(shm_id, NULL, SHM_EXEC);
	if(mapped_mem == MAP_FAILED){
		PERROR("shmat");
		return 1;
	}

	struct injcode_bearing br = prepare_bearing(&ctx);
	br.mapped_mem = mapped_mem;
	if(!realpath(argLib, br.libname))
	{
		PERROR("realpath");
		return 1;
	}
	
	struct ezinj_pl pl = prepare_payload(mapped_mem, br);

	int remote_shm_id = (int)CHECK(RCALL3(ctx, br.libc_shmget, ctx.target, MAPPINGSIZE, S_IRWXO));
	if(remote_shm_id < 0){
		ERR("Remote shmget failed: %d", remote_shm_id);
		return 1;
	}
	INFO("Shm id: %d", remote_shm_id);

	uintptr_t remote_shm_ptr = CHECK(RCALL3(ctx, br.libc_shmat, remote_shm_id, NULL, SHM_EXEC));
	if(remote_shm_ptr == (uintptr_t)MAP_FAILED){
		ERR("Remote shmat failed: %p", (void *)remote_shm_ptr);
		return 1;
	}

	#define PL_REMOTE(pl_addr) \
		( (void *)(remote_shm_ptr + PTRDIFF(pl_addr, mapped_mem)) )

	uintptr_t *target_sp = (uintptr_t *)(mapped_mem + MAPPINGSIZE - (sizeof(void *) * 2));
	target_sp[0] = (uintptr_t)PL_REMOTE(pl.code_start);
	target_sp[1] = (uintptr_t)PL_REMOTE(pl.br_start);
	
	DBGPTR(target_sp[0]);
	DBGPTR(target_sp[1]);

	uint8_t *target_syscall_ret = PL_REMOTE(pl.syscall_insn);

	if(shmdt(mapped_mem) < 0){
		PERROR("shmdt");
		return 1;
	}

	/* Make the call */
	/* Use the syscall->ret gadget to make the new thread safely "return" to its entrypoint */
	pid_t tid = CHECK(__RCALL(ctx, target_syscall_ret, __NR_clone, CLONE_FLAGS, (uintptr_t)PL_REMOTE(target_sp), 0));
	CHECK(tid);

	*pshm_id = shm_id;
	return 0;
}

int main(int argc, char *argv[]){
	if(argc != 3) {
		ERR("Usage: %s pid library-to-inject", argv[0]);
		return 1;
	}

	const char *argPid = argv[1];
	const char *argLib = argv[2];

	pid_t target = atoi(argPid);
	
	struct ezinj_ctx ctx;
	ctx.target = target;
	if(libc_init(&ctx) != 0){
		return 1;
	}
	
	CHECK(ptrace(PTRACE_ATTACH, target, 0, 0));

	int err = 0;
	/* Wait for attached process to stop */
	{
		int status = 0;
		do {
			waitpid(target, &status, 0);
		} while(!WIFSTOPPED(status));
	}
	
	do {
		int shm_id = -1;
		if((err = ezinject_main(ctx, argLib, &shm_id)) != 0){
			break;
		}
		
		if(shm_id > -1){
			// mark shared memory for deletion, when the process dies
			CHECK(shmctl(shm_id, IPC_RMID, NULL));
		}
	} while(0);
	CHECK(ptrace(PTRACE_DETACH, target, 0, 0));
	return err;
}
