#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <signal.h>
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
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/user.h>

#include "util.h"
#include "ezinject_injcode.h"

enum verbosity_level verbosity = V_DBG;

#include "ezinject_arch.h"

#define MEMALIGN 4 /* MUST be a power of 2 */
#define ALIGNMSK ~(MEMALIGN-1)

#define STRSZ(x) (strlen(x) + 1)

#define ALIGN(x) ((void *)(((uintptr_t)x + MEMALIGN) & ALIGNMSK))
#define PTRDIFF(a, b) ( ((uintptr_t)(a)) - ((uintptr_t)(b)) )

#define CLONE_FLAGS (CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_PARENT|CLONE_THREAD|CLONE_IO)

#define IS_IGNORED_SIG(x) ((x) == SIGUSR1 || (x) == SIGUSR2 || (x) >= SIGRTMIN)

typedef struct {
	uintptr_t remote;
	uintptr_t local;
} ez_addr;

#define EZ_LOCAL(ref, remote_addr) (ref.local + PTRDIFF(remote_addr, ref.remote))
#define EZ_REMOTE(ref, local_addr) (ref.remote + PTRDIFF(local_addr, ref.local))


uintptr_t remote_call(pid_t target, uintptr_t insn_addr, int nr, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
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

struct ezinj_str {
	int len;
	char *str;
};

struct ezinj_str ezstr_new(char *str){
	struct ezinj_str bstr = {
		.len = STRSZ(str),
		.str = str
	};
	return bstr;
}

struct ezinj_pl {
	struct injcode_bearing *br_start;
	uint8_t *code_start;
	uint8_t *syscall_insn;
	uint8_t *ret_insn;
};

int libc_init(struct ezinj_ctx *ctx){
	/**
	 * locate glibc in /proc/<pid>/maps
	 * both for local and remote procs
	 */
	ez_addr libc = {
		.local  = (uintptr_t) get_base(getpid(), "libc-"),
		.remote = (uintptr_t) get_base(ctx->target, "libc-")
	};

	DBGPTR(libc.remote);
	DBGPTR(libc.local);
	
	if(!libc.local || !libc.remote)
	{
		ERR("Failed to get libc base");
		return 1;
	}

	ez_addr libc_syscall = {
		.local  = (uintptr_t)&syscall,
		.remote = EZ_REMOTE(libc, &syscall)
	};

	ez_addr libc_syscall_insn = {
		.local = (uintptr_t)locate_gadget(
			(uint8_t *)libc_syscall.local, 0x1000,
			(uint8_t *)SYSCALL_INSN,
			sizeof(SYSCALL_INSN)
		),
	};

	DBGPTR(libc_syscall_insn.local);
	if(!libc_syscall_insn.local)
	{
		ERR("Failed to find syscall instruction in libc");
		return 1;
	}

	libc_syscall_insn.remote = EZ_REMOTE(libc, libc_syscall_insn.local);

	ctx->libc = libc;
	ctx->libc_syscall = libc_syscall;
	ctx->libc_syscall_insn = libc_syscall_insn;
	return 0;
}

void strPush(char **strData, struct ezinj_str str){
	memcpy(*strData, str.str, str.len);
	*strData += str.len;
}

struct injcode_bearing *prepare_bearing(struct ezinj_ctx ctx, int argc, char *argv[]){
	/**
	 * Rebase local symbols to remote
	 */
	#define SYM_ADDR(sym) { \
		.local = (uintptr_t) (sym), \
		.remote = (uintptr_t) EZ_REMOTE(ctx.libc, (uintptr_t)(sym)) \
	}

	ez_addr libc_dlopen_mode = SYM_ADDR(dlsym(RTLD_DEFAULT, "__libc_dlopen_mode"));

	char libName[PATH_MAX];
	if(!realpath(argv[0], libName))
	{
		PERROR("realpath");
		return NULL;
	}

	int dyn_ptr_size = argc * sizeof(char *);
	int dyn_str_size = 0;

	struct ezinj_str args[argc];
	args[0] = ezstr_new(libName);
	dyn_str_size += args[0].len;

	for(int i=1; i<argc; i++){
		args[i] = ezstr_new(argv[i]);
		dyn_str_size += args[i].len;
	}

	int dyn_total_size = dyn_ptr_size + dyn_str_size;

	struct injcode_bearing *br = malloc(sizeof(*br) + dyn_total_size);
	br->libc_syscall = (void *)ctx.libc_syscall.remote;
	br->libc_dlopen_mode = (void *)libc_dlopen_mode.remote;
	br->argc = argc;
	br->dyn_size = dyn_total_size;

	char *stringData = (char *)br + sizeof(*br) + dyn_ptr_size;
	for(int i=0; i<argc; i++){
		strPush(&stringData, args[i]);
	}
	return br;
}


struct ezinj_pl prepare_payload(void *mapped_mem, struct injcode_bearing *br){
	size_t injected_size = (size_t)PTRDIFF(injected_code_end, injected_code);
	DBG("injsize=%zu", injected_size);

	uint8_t *br_start = (uint8_t *)mapped_mem;
	uint8_t *code_start = ALIGN(br_start + sizeof(*br) + br->dyn_size);
	uint8_t *syscall_insn = ALIGN(code_start + injected_size);
	uint8_t *ret_insn = syscall_insn + sizeof(SYSCALL_INSN);

	memcpy(br_start, br, sizeof(*br) + br->dyn_size);
	memcpy(code_start, injected_code, injected_size);
	memcpy(syscall_insn, (void *)SYSCALL_INSN, sizeof(SYSCALL_INSN));
	memcpy(ret_insn, (void*)RET_INSN, sizeof(RET_INSN));

	struct injcode_bearing *shared_br = (struct injcode_bearing *)br_start;

	struct ezinj_pl pl = {
		.code_start = code_start,
		.syscall_insn = syscall_insn,
		.ret_insn = ret_insn,
		.br_start = shared_br
	};

	return pl;
}

#define UPTR(x) ((uintptr_t)x)
#define __RCALL(ctx, x, ...) remote_call(ctx.target, UPTR(x), __VA_ARGS__)
#define __RCALL_SC(ctx, n, ...) __RCALL(ctx, ctx.libc_syscall_insn.remote, n, __VA_ARGS__)

// Remote System Call
#define RSCALL0(ctx,n)               __RCALL_SC(ctx,n,0,0,0)
#define RSCALL1(ctx,n,a1)            __RCALL_SC(ctx,n,UPTR(a1),0,0)
#define RSCALL2(ctx,n,a1,a2)         __RCALL_SC(ctx,n,UPTR(a1),UPTR(a2),0)
#define RSCALL3(ctx,n,a1,a2,a3)      __RCALL_SC(ctx,n,UPTR(a1),UPTR(a2),UPTR(a3))

int ezinject_main(
	struct ezinj_ctx ctx,
	int argc, char *argv[],
	int *pshm_id,
	int *psem_id
){
	int shm_id, sem_id;

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

	if((sem_id = semget(ctx.target, 1, IPC_CREAT | IPC_EXCL | S_IRWXO)) < 0){
		perror("semget");
		return 1;
	}

	// set semaphore to 1
	struct sembuf sem_op = {
		.sem_num = 0,
		.sem_op = 1,
		.sem_flg = 0
	};
	if(semop(sem_id, &sem_op, 1) < 0){
		PERROR("semop");
		return 1;
	}

	// Allocate bearing: br is a *LOCAL* pointer
	struct injcode_bearing *br = prepare_bearing(ctx, argc, argv);
	if(br == NULL){
		return 1;
	}


	int err = 1;
	do {
		br->mapped_mem = mapped_mem;
	
		// Prepare payload in shm: pl contains pointers to *SHARED* memory
		struct ezinj_pl pl = prepare_payload(mapped_mem, br);

		// swap local br pointer with shared
		free(br);
		br = pl.br_start;

		int remote_shm_id = (int)CHECK(RSCALL3(ctx, __NR_shmget, ctx.target, MAPPINGSIZE, S_IRWXO));
		if(remote_shm_id < 0){
			ERR("Remote shmget failed: %d", remote_shm_id);
			break;
		}
		INFO("Shm id: %d", remote_shm_id);

		uintptr_t remote_shm_ptr = CHECK(RSCALL3(ctx, __NR_shmat, remote_shm_id, NULL, SHM_EXEC));
		if(remote_shm_ptr == (uintptr_t)MAP_FAILED){
			ERR("Remote shmat failed: %p", (void *)remote_shm_ptr);
			break;
		}

		#define PL_REMOTE(pl_addr) \
			( (void *)(remote_shm_ptr + PTRDIFF(pl_addr, mapped_mem)) )

		uintptr_t *target_sp = (uintptr_t *)(mapped_mem + MAPPINGSIZE - (sizeof(void *) * 2));
		target_sp[0] = (uintptr_t)PL_REMOTE(pl.code_start);
		target_sp[1] = (uintptr_t)PL_REMOTE(br);

		DBGPTR(target_sp[0]);
		DBGPTR(target_sp[1]);

		if(shmdt(mapped_mem) < 0){
			PERROR("shmdt");
			break;
		}

		/* Make the call */
		/* Use the syscall->ret gadget to make the new thread safely "return" to its entrypoint */
		uint8_t *target_syscall_ret = PL_REMOTE(pl.syscall_insn);
		pid_t tid = CHECK(__RCALL(ctx, target_syscall_ret, __NR_clone, CLONE_FLAGS, (uintptr_t)PL_REMOTE(target_sp), 0));
		CHECK(tid);

		err = 0;
	} while(0);

	if(err != 0){
		return err;
	}
	
	*pshm_id = shm_id;
	*psem_id = sem_id;
	return 0;
}

int main(int argc, char *argv[]){
	if(argc < 3) {
		ERR("Usage: %s pid library-to-inject", argv[0]);
		return 1;
	}

	const char *argPid = argv[1];
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
		for(;;){
			waitpid(target, &status, 0);
			if(WIFSTOPPED(status)){
				if(!IS_IGNORED_SIG(WSTOPSIG(status))){
					break;
				}
				CHECK(ptrace(PTRACE_CONT, target, 0, 0));
			}
		}
	}
	
	int shm_id = -1, sem_id = -1;
	err = ezinject_main(ctx, argc - 2, &argv[2], &shm_id, &sem_id);

	CHECK(ptrace(PTRACE_DETACH, target, 0, 0));

	if(err != 0){
		return err;
	}

	// wait for target to decrement shm
	struct sembuf sem_op = {
		.sem_num = 0,
		.sem_op = 0,
		.sem_flg = 0
	};
	if((err = semop(sem_id, &sem_op, 1)) < 0){
		PERROR("semop");
		return err;
	}

	INFO("Cleaning up IPC");
	CHECK(shmctl(shm_id, IPC_RMID, NULL));
	CHECK(semctl(sem_id, IPC_RMID, 0));
	return err;
}
