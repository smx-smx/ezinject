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

#include "config.h"

#ifdef EZ_ARCH_MIPS
#include <asm-generic/ipc.h>
#endif

#include "util.h"
#include "ezinject.h"
#include "ezinject_arch.h"
#include "ezinject_injcode.h"

enum verbosity_level verbosity = V_DBG;

static struct ezinj_ctx ctx; // only to be used for sigint handler

static ez_region region_pl_code = {
	.start = (void *)&injected_code_start,
	.end = (void *)&injected_code_end
};

static ez_region region_sc_insn = {
	.start = (void *)&injected_sc_start,
	.end = (void *)&injected_sc_end
};

void setregs_callstack(
	struct user *orig_ctx,
	struct user *new_ctx,
	void *pUserData
){
	UNUSED(orig_ctx);

	struct call_req *call = (struct call_req *)pUserData;
	struct callstack_req cs = call->u.call;

	REG(*new_ctx, REG_PC) = call->insn_addr;
	REG(*new_ctx, REG_SP) = cs.stack_addr;
}

void setregs_syscall(
	struct user *orig_ctx,
	struct user *new_ctx,
	void *pUserData
){
	struct call_req *call = (struct call_req *)pUserData;
	struct sc_req sc = call->u.syscall;

	REG(*new_ctx, REG_PC) = call->insn_addr;
	REG(*new_ctx, REG_NR) = sc.nr;
	REG(*new_ctx, REG_ARG1) = sc.arg1;
	REG(*new_ctx, REG_ARG2) = sc.arg2;
	REG(*new_ctx, REG_ARG3) = sc.arg3;

#ifdef EZ_ARCH_MIPS
	REG(*new_ctx, REG_ARG4) = sc.arg4;
#else
	REG(*new_ctx, REG_ARG4) = 0;
	REG(*new_ctx, REG_ARG5) = 0;
#endif

#ifdef EZ_ARCH_I386
	//ebp must point to valid stack
	REG(*new_ctx, REG_ARG6) = REG(*orig_ctx, REG_SP);
#else
	UNUSED(orig_ctx);
#ifndef EZ_ARCH_MIPS
	REG(*new_ctx, REG_ARG6) = 0;
#endif
#endif

	DBG("remote_call(%u)", (unsigned int)sc.nr);
}

uintptr_t remote_call_common(pid_t target, pfnRegSet setRegs, void *pUserData){
	struct user orig_ctx, new_ctx;
	memset(&orig_ctx, 0x00, sizeof(orig_ctx));

	ptrace(PTRACE_GETREGS, target, 0, &orig_ctx);
	memcpy(&new_ctx, &orig_ctx, sizeof(orig_ctx));

	setRegs(&orig_ctx, &new_ctx, pUserData);

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
	DBG("[RET] = %zu", (uintptr_t)REG(new_ctx, REG_RET));

	struct call_req *call = (struct call_req *)pUserData;
	DBG("PC: %p => %p",
		(void *)call->insn_addr,
		(void *)REG(new_ctx, REG_PC));

	return REG(new_ctx, REG_RET);
}

uintptr_t remote_call_stack(
	pid_t target,
	uintptr_t insn_addr,
	uintptr_t stack_addr
){
	struct call_req req = {
		.insn_addr = insn_addr,
		.u.call = {
			.stack_addr = stack_addr
		}
	};
	return remote_call_common(target, &setregs_callstack, &req);
}

uintptr_t remote_call(
	pid_t target,
	uintptr_t insn_addr, int nr,
	uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
	uintptr_t arg4
){
	struct call_req req = {
		.insn_addr = insn_addr,
		.u.syscall = {
			.nr = nr,
			.arg1 = arg1,
			.arg2 = arg2,
			.arg3 = arg3,
			.arg4 = arg4
		}
	};
	return remote_call_common(target, &setregs_syscall, &req);
}

struct ezinj_str ezstr_new(char *str){
	struct ezinj_str bstr = {
		.len = STRSZ(str),
		.str = str
	};
	return bstr;
}

ez_addr sym_addr(void *handle, const char *sym_name, ez_addr lib){
	uintptr_t sym_addr = (uintptr_t)dlsym(handle, sym_name);
	ez_addr sym = {
		.local = sym_addr,
		.remote = EZ_REMOTE(lib, sym_addr)
	};
	return sym;
}

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

	if(!libc.local || !libc.remote) {
		ERR("Failed to get libc base");
		return 1;
	}
	ctx->libc = libc;

	void *h_libc = dlopen(C_LIBRARY_NAME, RTLD_LAZY);
	if(!h_libc){
		ERR("dlopen("C_LIBRARY_NAME") failed: %s", dlerror());
		return 1;
	}

#if defined(HAVE_LIBC_DLOPEN_MODE)
	ez_addr libc_dlopen = sym_addr(h_libc, "__libc_dlopen_mode", libc);
#elif defined(HAVE_DL_LOAD_SHARED_LIBRARY)
	ez_addr ldso = {
		.local = (uintptr_t)get_base(getpid(), "ld-uClibc"),
		.remote = (uintptr_t)get_base(ctx->target, "ld-uClibc")
	};
	if(!ldso.local || !ldso.remote){
		ERR("Failed to get ldso base");
		return 1;
	}

	void *h_ldso = dlopen(DYN_LINKER_NAME, RTLD_LAZY);
	if(!h_ldso){
		ERR("dlopen("DYN_LINKER_NAME") failed: %s", dlerror());
		return 1;
	}

	{
		void *h_libdl = dlopen(DL_LIBRARY_NAME, RTLD_LAZY);
		if(!h_libdl){
			ERR("dlopen("DL_LIBRARY_NAME") failed: %s", dlerror());
			return 1;
		}

		ez_addr libdl = {
			.local = (uintptr_t)get_base(getpid(), "libdl"),
			.remote = (uintptr_t)get_base(ctx->target, "libdl")
		};

		DBGPTR(libdl.local);
		DBGPTR(libdl.remote);

		if(libdl.remote != 0){
			// target has libdl loaded. this makes things easier for us
			ctx->actual_dlopen = sym_addr(h_libdl, "dlopen", libdl);
		} else {
			// target has no libdl loaded. we will need to load it ourselves
			void *dlopen_local = dlsym(h_libdl, "dlopen");
			off_t dlopen_offset = (off_t)PTRDIFF(dlopen_local, libdl.local);
			DBG("dlopen offset: 0x%lx", dlopen_offset);
			ctx->dlopen_offset = dlopen_offset;
		}

		dlclose(h_libdl);
	}


	ez_addr libc_dlopen = sym_addr(h_ldso, "_dl_load_shared_library", ldso);

	ez_addr uclibc_sym_tables = sym_addr(h_ldso, "_dl_symbol_tables", ldso);
	ez_addr uclibc_loaded_modules = sym_addr(h_ldso, "_dl_loaded_modules", ldso);

#ifdef EZ_ARCH_MIPS
	ez_addr uclibc_mips_got_reloc = sym_addr(h_ldso, "_dl_perform_mips_global_got_relocations", ldso);
	DBGPTR(uclibc_mips_got_reloc.local);
	DBGPTR(uclibc_mips_got_reloc.remote);
	ctx->uclibc_mips_got_reloc = uclibc_mips_got_reloc;
#endif

	ez_addr uclibc_dl_fixup = sym_addr(h_ldso, "_dl_fixup", ldso);

	DBGPTR(uclibc_sym_tables.local);
	DBGPTR(uclibc_sym_tables.remote);
	ctx->uclibc_sym_tables = uclibc_sym_tables;

	DBGPTR(uclibc_loaded_modules.local);
	DBGPTR(uclibc_loaded_modules.remote);
	ctx->uclibc_loaded_modules = uclibc_loaded_modules;

	DBGPTR(uclibc_dl_fixup.local);
	DBGPTR(uclibc_dl_fixup.remote);
	ctx->uclibc_dl_fixup = uclibc_dl_fixup;

	dlclose(h_ldso);
#endif
	DBGPTR(libc_dlopen.local);
	DBGPTR(libc_dlopen.remote);
	ctx->libc_dlopen = libc_dlopen;

	ez_addr libc_clone = sym_addr(h_libc, "clone", libc);
	DBGPTR(libc_clone.local);
	DBGPTR(libc_clone.remote);
	ctx->libc_clone = libc_clone;

	ez_addr libc_syscall = sym_addr(h_libc, "syscall", libc);
	DBGPTR(libc_syscall.local);
	DBGPTR(libc_syscall.remote);
	ctx->libc_syscall = libc_syscall;

	dlclose(h_libc);
	return 0;
}


void strPush(char **strData, struct ezinj_str str){
	memcpy(*strData, str.str, str.len);
	*strData += str.len;
}


struct injcode_bearing *prepare_bearing(struct ezinj_ctx ctx, int argc, char *argv[]){
	int dyn_ptr_size = argc * sizeof(char *);
	int dyn_str_size = 0;

	int num_strings;

#ifdef HAVE_DL_LOAD_SHARED_LIBRARY
	num_strings = argc + 1; // add libdl.so name
#else
	num_strings = argc;
#endif

	struct ezinj_str args[num_strings];
	int argi = 0;

#ifdef HAVE_DL_LOAD_SHARED_LIBRARY
	{ //libdl.so name (without path)
		args[argi] = ezstr_new(DL_LIBRARY_NAME);
		dyn_str_size += args[argi].len;
		argi++;
	}
#endif

	{ //library to load
		char libName[PATH_MAX];
		if(!realpath(argv[0], libName))
		{
			ERR("realpath: %s", libName);
			PERROR("realpath");
			return NULL;
		}

		args[argi] = ezstr_new(libName);
		dyn_str_size += args[argi].len;
		argi++;
	}

	// user arguments
	for(int i=1; i < argc; i++, argi++){
		args[argi] = ezstr_new(argv[i]);
		dyn_str_size += args[i].len;
	}

	int dyn_total_size = dyn_ptr_size + dyn_str_size;

	struct injcode_bearing *br = malloc(sizeof(*br) + dyn_total_size);
	br->libc_clone = (void *)ctx.libc_clone.remote;
	br->libc_dlopen = (void *)ctx.libc_dlopen.remote;
	br->actual_dlopen = (void *)ctx.actual_dlopen.remote;
#ifdef HAVE_DL_LOAD_SHARED_LIBRARY
	br->uclibc_sym_tables = (void *)ctx.uclibc_sym_tables.remote;
	br->uclibc_dl_fixup = (void *)ctx.uclibc_dl_fixup.remote;
	br->uclibc_loaded_modules = (void *)ctx.uclibc_loaded_modules.remote;
#ifdef EZ_ARCH_MIPS
	br->uclibc_mips_got_reloc = (void *)ctx.uclibc_mips_got_reloc.remote;
#endif
	br->dlopen_offset = ctx.dlopen_offset;
#endif
	br->libc_syscall = (void *)ctx.libc_syscall.remote;
	br->argc = argc;
	br->dyn_size = dyn_total_size;

	char *stringData = (char *)br + sizeof(*br) + dyn_ptr_size;
	for(int i=0; i<num_strings; i++){
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
#define RSCALL0(ctx,n)               __RCALL_SC(ctx,n,0,0,0,0)
#define RSCALL1(ctx,n,a1)            __RCALL_SC(ctx,n,UPTR(a1),0,0,0)
#define RSCALL2(ctx,n,a1,a2)         __RCALL_SC(ctx,n,UPTR(a1),UPTR(a2),0,0)
#define RSCALL3(ctx,n,a1,a2,a3)      __RCALL_SC(ctx,n,UPTR(a1),UPTR(a2),UPTR(a3),0)
#define RSCALL4(ctx,n,a1,a2,a3,a4)   __RCALL_SC(ctx,n,UPTR(a1),UPTR(a2),UPTR(a3),UPTR(a4))

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

	FILE *hmem = mem_open(ctx->target);
	if(hmem == NULL){
		PERROR("fopen");
		return 1;
	}

	uintptr_t codeBase = get_code_base(ctx->target);
	if(codeBase == 0){
		ERR("Could not obtain code base");
		return 1;
	}

	size_t dataLength = REGION_LENGTH(region_sc_insn);
	uint8_t dataBak[dataLength];
	{
		if(fseek(hmem, codeBase, SEEK_SET) != 0){
			PERROR("fseek (pre-read)");
		} else if(fread(dataBak, 1, dataLength, hmem) != dataLength){
			PERROR("fread");
		} else if(fseek(hmem, codeBase, SEEK_SET) != 0){
			PERROR("fseek (pre-write)");
		} else if(fwrite((uint8_t *)region_sc_insn.start, 1, dataLength, hmem) != dataLength){
			PERROR("fwrite");
		}
		fflush(hmem);

		ctx->syscall_insn.remote = codeBase;
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

#ifdef HAVE_SHM_SYSCALLS
		int remote_shm_id = (int)CHECK(RSCALL3(ctx, __NR_shmget, ctx->target, MAPPINGSIZE, S_IRWXO));
#else
		int remote_shm_id = (int)CHECK(RSCALL4(ctx, __NR_ipc, SHMGET, ctx->target, MAPPINGSIZE, S_IRWXO));
#endif
		if(remote_shm_id < 0){
			ERR("Remote shmget failed: %d", remote_shm_id);
			break;
		}
		INFO("Shm id: %d", remote_shm_id);

#ifdef HAVE_SHM_SYSCALLS
		uintptr_t remote_shm_ptr = CHECK(RSCALL3(ctx, __NR_shmat, remote_shm_id, NULL, SHM_EXEC));
#else
		uintptr_t remote_shm_ptr = CHECK(RSCALL4(ctx, __NR_ipc, SHMAT, remote_shm_id, NULL, SHM_EXEC));
#endif
		if(remote_shm_ptr == (uintptr_t)MAP_FAILED){
			ERR("Remote shmat failed: %p", (void *)remote_shm_ptr);
			break;
		}

		#define PL_REMOTE(pl_addr) \
			UPTR(remote_shm_ptr + PTRDIFF(pl_addr, mapped_mem))

		#define PL_REMOTE_CODE(addr) \
			PL_REMOTE(pl.code_start) + PTRDIFF(addr, &injected_code_start)

		// clone entry
		uintptr_t remote_clone_entry = PL_REMOTE_CODE(&injected_clone_entry);

		// stack base
		uintptr_t *target_sp = (uintptr_t *)((uintptr_t)STACKALIGN(mapped_mem + MAPPINGSIZE - STACKSIZE));

		// end of stack: used for arguments
		uintptr_t *stack_argv = (uintptr_t *)(
			(uintptr_t)target_sp + STACKSIZE - sizeof(uintptr_t) * 3
		);

		DBGPTR(target_sp);

		// br argument
		stack_argv[0] = PL_REMOTE(pl.br_start);
		// clone_fn
		stack_argv[1] = PL_REMOTE_CODE(&clone_fn);
		// pointer to this stack itself
		stack_argv[2] = PL_REMOTE(target_sp);

		DBGPTR(stack_argv[0]);
		DBGPTR(stack_argv[1]);
		DBGPTR(stack_argv[2]);

		{
			if(fseek(hmem, codeBase, SEEK_SET) != 0){
				PERROR("fseek (restore pre-write)");
			} else if(fwrite(dataBak, 1, dataLength, hmem) != dataLength){
				PERROR("fwrite (restore)");
			}
		}

		DBGPTR(remote_clone_entry);
		pid_t tid = remote_call_stack(
			ctx->target,
			remote_clone_entry,
			(uintptr_t)PL_REMOTE(stack_argv)
		);

		CHECK(tid);

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

int main(int argc, char *argv[]){
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
