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

static struct ezinj_ctx ctx; // only to be used for sigint handler


#include "ezinject.h"
#include "ezinject_arch.h"

#ifdef HAVE_LIBC_DLOPEN_MODE
extern void *__libc_dlopen_mode  (const char *__name, int __mode);
#endif

uintptr_t remote_call_stack(
	pid_t target,
	uintptr_t insn_addr,
	uintptr_t stack_addr
){
	struct user orig_ctx, new_ctx;
	memset(&orig_ctx, 0x00, sizeof(orig_ctx));

	ptrace(PTRACE_GETREGS, target, 0, &orig_ctx);
	memcpy(&new_ctx, &orig_ctx, sizeof(orig_ctx));

	REG(new_ctx, REG_PC) = insn_addr;
	REG(new_ctx, REG_SP) = stack_addr;

	ptrace(PTRACE_SETREGS, target, 0, &new_ctx);

	ptrace(PTRACE_SYSCALL, target, 0, 0); /* Run until syscall entry */
	if(waitpid(target, 0, 0) != target){
		PERROR("waitpid");
	}
	ptrace(PTRACE_SYSCALL, target, 0, 0); /* Run until syscall return */
	if(waitpid(target, 0, 0) != target){
		PERROR("waitpid");
	}
	ptrace(PTRACE_GETREGS, target, 0, &new_ctx); /* Get return value */
	
	ptrace(PTRACE_SETREGS, target, 0, &orig_ctx);
	DBG("remote_call_stack() PC: %p => %p",
		(void *)insn_addr, (void *)REG(new_ctx, REG_PC)
	);

	return REG(new_ctx, REG_RET);
}

uintptr_t remote_call(
	pid_t target,
	uintptr_t insn_addr, int nr,
	uintptr_t arg1, uintptr_t arg2, uintptr_t arg3
){
	struct user orig_ctx, new_ctx;
	memset(&orig_ctx, 0x00, sizeof(orig_ctx));

	ptrace(PTRACE_GETREGS, target, 0, &orig_ctx);
	memcpy(&new_ctx, &orig_ctx, sizeof(orig_ctx));

	REG(new_ctx, REG_PC) = insn_addr;
	REG(new_ctx, REG_NR) = nr;
	REG(new_ctx, REG_ARG1) = arg1;
	REG(new_ctx, REG_ARG2) = arg2;
	REG(new_ctx, REG_ARG3) = arg3;

#ifndef EZ_ARCH_MIPS
	REG(new_ctx, REG_ARG4) = 0;
	REG(new_ctx, REG_ARG5) = 0;
#endif

#ifdef EZ_ARCH_I386
	//ebp must point to valid stack
	REG(new_ctx, REG_ARG6) = REG(orig_ctx, REG_SP);
#else
#ifndef EZ_ARCH_MIPS
	REG(new_ctx, REG_ARG6) = 0;
#endif
#endif

	ptrace(PTRACE_SETREGS, target, 0, &new_ctx);

	ptrace(PTRACE_SYSCALL, target, 0, 0); /* Run until syscall entry */
	if(waitpid(target, 0, 0) != target){
		PERROR("waitpid");
	}
	ptrace(PTRACE_SYSCALL, target, 0, 0); /* Run until syscall return */
	if(waitpid(target, 0, 0) != target){
		PERROR("waitpid");
	}
	ptrace(PTRACE_GETREGS, target, 0, &new_ctx); /* Get return value */
	
	ptrace(PTRACE_SETREGS, target, 0, &orig_ctx);
	DBG("remote_call(%d) = %zu, PC: %p => %p",
		nr,
		(uintptr_t)REG(new_ctx, REG_RET),
		(void *)insn_addr,
		(void *)REG(new_ctx, REG_PC));

	return REG(new_ctx, REG_RET);
}

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
	uint8_t *sc_ret;
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
	ctx->libc = libc;

	ez_addr libc_clone = {
		.local = (uintptr_t)&clone,
		.remote = EZ_REMOTE(libc, &clone)
	};
	ctx->libc_clone = libc_clone;

	return 0;
}

size_t find_adj_bytes(FILE *src, size_t sz, unsigned char ch, size_t nmemb){
	size_t i;
	int fch;
	do {
		for(i=0; i < sz && (fch=fgetc(src)) == ch; i++);
	} while(i < sz && fch != EOF && i != nmemb);

	DBG("cnt[%02X] => %zu", ch, i);
	return i;
}

FILE *mem_open(struct ezinj_ctx *ctx){
	char line[256];
	snprintf(line, sizeof(line), "/proc/%u/mem", ctx->target);
	return fopen(line, "rb+");
}

uintptr_t find_cave(struct ezinj_ctx *ctx, FILE *hmem, size_t dataLength){
	char line[256];

	snprintf(line, sizeof(line), "/proc/%u/maps", ctx->target);
	FILE *fp = fopen(line, "r");
	if(fp == NULL){
		PERROR("fopen maps");
		return 0;
	}

	uintptr_t start, end;
	char perms[8];
	memset(perms, 0x00, sizeof(perms));

	int val;
	uintptr_t cave_addr = 0;
	while(cave_addr == 0){
		if(!fgets(line, sizeof(line), fp)){
			PERROR("fgets");
			break;			
		}
		val = sscanf(line, "%p-%p %s %*p %*x:%*x %*u %*s", (void **)&start, (void **)&end, (char *)&perms);
		if(val == 0){
			break;
		}

		if(strchr(perms, 'x') != NULL){
			size_t mem_length = end - start;

			INFO("Scanning cave: %p - %p", (void *)start, (void *)end);

			if(fseek(hmem, start, SEEK_SET) != 0){
				INFO("unreadable");
				continue;
			}

			size_t cave_size = 0;
			long int mempos;
			do {
				cave_size = find_adj_bytes(hmem, mem_length, 0x00, dataLength);
				mempos = ftell(hmem);
			} while(
				cave_size < dataLength &&
				mempos > -1 &&
				(uintptr_t)mempos < end
			);

			if(cave_size >= dataLength){
				INFO("Cave found (size:%zu)", cave_size);
				if(fseek(hmem, -cave_size, SEEK_CUR) != 0){
					PERROR("fseek");
					break;
				}
				cave_addr = ftell(hmem);

#if defined(EZ_ARCH_ARM) || defined(EZ_ARCH_MIPS)
				uintptr_t cave_addr_aligned = (uintptr_t)MEMALIGN(cave_addr);
				// check if we're word aligned
				int rem = cave_addr_aligned - cave_addr;
				if(rem != 0 && cave_size > 0){
					if((cave_size - rem) < dataLength){
						// no room to remove 1 byte, continue searching
						cave_addr = 0;
					} else {
						cave_size -= rem;
						cave_addr += rem;
					}
				}
#endif
			}
		}
	}

	fclose(fp);

	return cave_addr;
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

#ifdef HAVE_LIBC_DLOPEN_MODE
	ez_addr libc_dlopen_mode = SYM_ADDR(&__libc_dlopen_mode);
#else
	ez_addr libc_dlopen_mode = SYM_ADDR(&dlopen);
#endif
	DBGPTR(libc_dlopen_mode.local);
	DBGPTR(libc_dlopen_mode.remote);

	char libName[PATH_MAX];
	if(!realpath(argv[0], libName))
	{
		ERR("realpath: %s", libName);
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
	br->libc_clone = (void *)ctx.libc_clone.remote;
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
	size_t br_size = sizeof(*br) + br->dyn_size;
	size_t injected_size = REGION_LENGTH(region_pl_code);
	DBG("injsize=%zu", injected_size);

	uint8_t *br_start = (uint8_t *)mapped_mem;

	uint8_t *code_start = MEMALIGN(br_start + br_size);

	DBG("dyn_size=%u", br->dyn_size);

	memcpy(br_start, br, br_size);
	memcpy(code_start, region_pl_code.start, injected_size);
	hexdump(code_start, injected_size);

	struct ezinj_pl pl = {
		.code_start = code_start,
		.br_start = (struct injcode_bearing *)br_start
	};

	return pl;
}

#define __RCALL(ctx, x, ...) remote_call(ctx->target, UPTR(x), __VA_ARGS__)
#define __RCALL_SC(ctx, n, ...) __RCALL(ctx, ctx->syscall_insn.remote, n, __VA_ARGS__)

// Remote System Call
#define RSCALL0(ctx,n)               __RCALL_SC(ctx,n,0,0,0)
#define RSCALL1(ctx,n,a1)            __RCALL_SC(ctx,n,UPTR(a1),0,0)
#define RSCALL2(ctx,n,a1,a2)         __RCALL_SC(ctx,n,UPTR(a1),UPTR(a2),0)
#define RSCALL3(ctx,n,a1,a2,a3)      __RCALL_SC(ctx,n,UPTR(a1),UPTR(a2),UPTR(a3))

void cleanup_ipc(struct ezinj_ctx *ctx){
	if(ctx->sem_id > -1){
		CHECK(semctl(ctx->sem_id, IPC_RMID, 0));
		ctx->sem_id = -1;
	}
	if(ctx->shm_id > -1){
		CHECK(shmctl(ctx->shm_id, IPC_RMID, NULL));
		ctx->shm_id = -1;
	}
	if(ctx->mapped_mem != NULL){
		CHECK(shmdt(ctx->mapped_mem));
		ctx->mapped_mem = NULL;
	}
}

void sigint_handler(int signum){
	UNUSED(signum);
	cleanup_ipc(&ctx);
}

int ezinject_main(
	struct ezinj_ctx *ctx,
	int argc, char *argv[]
){
	int shm_id, sem_id;

	FILE *hmem = mem_open(ctx);
	if(hmem == NULL){
		PERROR("fopen");
		return 1;
	}

	uintptr_t cave_addr = 0;
	{ // write syscall instruction
		size_t dataLength = REGION_LENGTH(region_sc_insn);

		cave_addr = find_cave(ctx, hmem, dataLength);
		if(cave_addr == 0){
			ERR("Could not find code cave");
			return 1;			
		}
		DBGPTR(cave_addr);

		if(fseek(hmem, cave_addr, SEEK_SET) != 0){
			PERROR("fseek");
		} else if(fwrite((uint8_t *)region_sc_insn.start, 1, dataLength, hmem) != dataLength){
			PERROR("fwrite");
		}
		fflush(hmem);

		ctx->syscall_insn.remote = cave_addr;
	}

	/* Verify that remote_call works correctly */
	pid_t remote_pid = (pid_t)RSCALL0(ctx, __NR_getpid);
	if(remote_pid != ctx->target)
	{
		ERR("Remote syscall returned incorrect result!");
		ERR("Expected: %u, actual: %u", ctx->target, remote_pid);
		return 1;
	}

	signal(SIGINT, sigint_handler);

	if((shm_id = shmget(ctx->target, MAPPINGSIZE, IPC_CREAT | IPC_EXCL | S_IRWXO)) < 0){
		PERROR("shmget");
		return 1;
	}

	void *mapped_mem = shmat(shm_id, NULL, SHM_EXEC);
	if(mapped_mem == MAP_FAILED){
		PERROR("shmat");
		return 1;
	}

	if((sem_id = semget(ctx->target, 1, IPC_CREAT | IPC_EXCL | S_IRWXO)) < 0){
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
	struct injcode_bearing *br = prepare_bearing(*ctx, argc, argv);
	if(br == NULL){
		return 1;
	}

	int err = 1;
	do {
		// Prepare payload in shm: pl contains pointers to *SHARED* memory
		struct ezinj_pl pl = prepare_payload(mapped_mem, br);

		// swap local br pointer with shared
		free(br);

		int remote_shm_id = (int)CHECK(RSCALL3(ctx, __NR_shmget, ctx->target, MAPPINGSIZE, S_IRWXO));
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
			UPTR(remote_shm_ptr + PTRDIFF(pl_addr, mapped_mem))

		#define PL_REMOTE_CODE(addr) \
			(uintptr_t)PL_REMOTE(pl.code_start) + PTRDIFF(addr, &injected_code_start)

		// clone entry
		uintptr_t remote_clone_entry = PL_REMOTE_CODE(&injected_clone);

		uintptr_t *target_sp = (uintptr_t *)((uintptr_t)STACKALIGN(mapped_mem + MAPPINGSIZE - sizeof(uintptr_t) * 8));
		DBGPTR(mapped_mem + MAPPINGSIZE);
		DBGPTR(target_sp);

		// br argument
		target_sp[0] = PL_REMOTE(pl.br_start);
		// clone_fn
		target_sp[1] = PL_REMOTE_CODE(&clone_fn);
		// pointer to this stack itself
		target_sp[2] = PL_REMOTE(target_sp);

		DBGPTR(target_sp[0]);
		DBGPTR(target_sp[1]);
		DBGPTR(target_sp[2]);

		DBGPTR(remote_clone_entry);
		pid_t tid = remote_call_stack(
			ctx->target,
			remote_clone_entry,
			(uintptr_t)PL_REMOTE(target_sp)
		);

		CHECK(tid);

		{ // restore zeros in code cave
			fseek(hmem, cave_addr, SEEK_SET);
			uint8_t zeroBuf[REGION_LENGTH(region_sc_insn)];
			memset(zeroBuf, 0x00, sizeof(zeroBuf));
			fwrite(zeroBuf, 1, sizeof(zeroBuf), hmem);
			fflush(hmem);
		}

		err = 0;
	} while(0);

	if(err != 0){
		return err;
	}

	fclose(hmem);
	ctx->sem_id = sem_id;
	ctx->shm_id = shm_id;
	ctx->mapped_mem = mapped_mem;
	return 0;
}

/**
 * Make sure there is no padding between functions
 **/
int compiler_check(){
	int padding;
	if((padding = PTRDIFF(&injected_clone_entry, &injected_clone)) != 0){
		ERR("Expected padding:0, actual:%d, check your compiler flags", padding);
		return 1;
	}
	return 0;
}

int main(int argc, char *argv[]){
	if(compiler_check() != 0){
		return 1;
	}

	if(argc < 3) {
		ERR("Usage: %s pid library-to-inject", argv[0]);
		return 1;
	}

	const char *argPid = argv[1];
	pid_t target = atoi(argPid);

	CHECK(ptrace(PTRACE_ATTACH, target, 0, 0));

	//struct ezinj_ctx ctx;
	ctx.target = target;
	if(libc_init(&ctx) != 0){
		return 1;
	}

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
	
	err = ezinject_main(&ctx, argc - 2, &argv[2]);

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
	if((err = semop(ctx.sem_id, &sem_op, 1)) < 0){
		PERROR("semop");
		return err;
	}

	INFO("Cleaning up IPC");
	cleanup_ipc(&ctx);
	return err;
}
