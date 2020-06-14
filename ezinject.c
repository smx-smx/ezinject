#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <link.h>
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

#include "config.h"

#ifndef HAVE_SHM_SYSCALLS
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

int allocate_shm(struct ezinj_ctx *ctx, size_t dyn_total_size, struct ezinj_pl *layout, size_t *allocated_size);

void setregs_syscall(
	regs_t *orig_ctx,
	regs_t *new_ctx,
	struct call_req call
){
	struct sc_req sc = call.syscall;

	REG(*new_ctx, REG_PC) = call.insn_addr;

	if(SC_HAS_ARG(sc, 0)){
		REG(*new_ctx, REG_NR)   = sc.argv[0];
		REG(*new_ctx, REG_ARG1) = sc.argv[1];
		REG(*new_ctx, REG_ARG2) = sc.argv[2];
		REG(*new_ctx, REG_ARG3) = sc.argv[3];
		REG(*new_ctx, REG_ARG4) = sc.argv[4];

		DBG("remote_call(%u)", (unsigned int)sc.argv[0]);
	}

	if(call.stack_addr != 0){
		REG(*new_ctx, REG_SP) = call.stack_addr;
	}

#ifdef EZ_ARCH_I386
	//ebp must point to valid stack
	REG(*new_ctx, REG_ARG6) = REG(*orig_ctx, REG_SP);
#else
	UNUSED(orig_ctx);
#endif

}

void remote_call_setup(pid_t target, struct call_req call, regs_t *orig_ctx, regs_t *new_ctx){
	memset(orig_ctx, 0x00, sizeof(*orig_ctx));

	ptrace(PTRACE_GETREGS, target, 0, orig_ctx);
	memcpy(new_ctx, orig_ctx, sizeof(*orig_ctx));

	setregs_syscall(orig_ctx, new_ctx, call);
	ptrace(PTRACE_SETREGS, target, 0, new_ctx);
}

int remote_wait(pid_t target){
	int rc;
	int status;
	do {
		rc = waitpid(target, &status, 0);
		if(rc < 0){
			PERROR("waitpid");
			return rc;
		}
	} while(rc != target);

	if(!WIFSTOPPED(status)){
		ERR("remote did not stop");
		return -1;
	}

	return status;
}

#define SC_EVENT_STATUS (SIGTRAP | 0x80)

uintptr_t remote_call_common(pid_t target, struct call_req call){
	regs_t orig_ctx, new_ctx;
	remote_call_setup(target, call, &orig_ctx, &new_ctx);

	int status;
	for(int i=0; i<call.num_wait_calls; i++){
		uintptr_t sc_ret;
		int rc;
		do {
			if(ptrace(PTRACE_SYSCALL, target, 0, 0) < 0){ /* Run until syscall entry */
				PERROR("ptrace");
				return -1;
			}
			status = remote_wait(target);
			if((rc=WSTOPSIG(status)) != SC_EVENT_STATUS){
				ERR("remote_wait: %s", strsignal(rc));
				return -1;
			}

			ptrace(PTRACE_SYSCALL, target, 0, 0); /* Run until syscall return */
			status = remote_wait(target);
			if((rc=WSTOPSIG(status)) != SC_EVENT_STATUS){
				ERR("remote_wait: %s", strsignal(rc));
				return -1;
			}

			// get syscall return value
			if(ptrace(PTRACE_GETREGS, target, 0, &new_ctx) < 0){ /* Get return value */
				PERROR("ptrace");
				return -1;
			}

			sc_ret = REG(new_ctx, REG_RET);
			DBG("[RET] = %zu", sc_ret);

			if((signed int)sc_ret == -EINTR){
				remote_call_setup(target, call, &orig_ctx, &new_ctx);
			}
		} while((signed int)sc_ret == -EINTR);
	}

	if(call.num_wait_calls == 0){
		int stopsig = 0;
		do {

			DBG("continuing...");
			// pass signal to child
			if(ptrace(PTRACE_CONT, target, 0, stopsig) < 0){
				PERROR("ptrace");
				return -1;
			}

			// wait for the children to stop
			status = remote_wait(target);

			stopsig = WSTOPSIG(status);
			DBG("got signal: %d (%s)", stopsig, strsignal(stopsig));
		} while(IS_IGNORED_SIG(stopsig));

		if(ptrace(PTRACE_GETREGS, target, 0, &new_ctx) < 0){
			PERROR("ptrace");
			return -1;
		}

		if(stopsig != SIGSTOP){
			ERR("Unexpected signal (expected SIGSTOP)");

			#ifdef DEBUG
			regs_t tmp;
			ptrace(PTRACE_GETREGS, target, 0, &tmp);
			DBG("CRASH @ %p (offset: %i)",
				(void *)REG(tmp, REG_PC),
				(signed int)(REG(tmp, REG_PC) - call.insn_addr)
			);
			#endif
		}

		if(stopsig == SIGTRAP || stopsig == SIGSEGV){
			// child raised a debug event
			// this is a debug condition, so do a hard exit
			// $TODO: do it nicer
			ptrace(PTRACE_DETACH, target, 0, 0);
			exit(0);
			return -1;
		}
	}

	ptrace(PTRACE_SETREGS, target, 0, &orig_ctx);

#ifdef DEBUG
	DBG("PC: %p => %p",
		(void *)call.insn_addr,
		(void *)((uintptr_t)REG(new_ctx, REG_PC)));
#endif

	return REG(new_ctx, REG_RET);
}

uintptr_t remote_call(
	pid_t target,
	uintptr_t stack_addr,
	uintptr_t insn_addr,
	int num_wait_calls,
	unsigned int argmask, ...
){
	struct call_req req = {
		.insn_addr = insn_addr,
		.stack_addr = stack_addr,
		.num_wait_calls = num_wait_calls
	};

	va_list ap;
	va_start(ap, argmask);

	struct sc_req sc;
	sc.argmask = argmask;

	for(int i=0; i<SC_MAX_ARGS; i++){
		sc.argv[i] = (SC_HAS_ARG(sc, i)) ? va_arg(ap, uintptr_t) : 0;
	}
	req.syscall = sc;

	return remote_call_common(target, req);
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
	char *ignores[] = {"ld-", NULL};
	ez_addr libc = {
		.local  = (uintptr_t) get_base(getpid(), "libc", ignores),
		.remote = (uintptr_t) get_base(ctx->target, "libc", ignores)
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

	{
		void *h_libdl = dlopen(DL_LIBRARY_NAME, RTLD_LAZY);
		if(!h_libdl){
			ERR("dlopen("DL_LIBRARY_NAME") failed: %s", dlerror());
			return 1;
		}

		ez_addr libdl = {
			.local = (uintptr_t)get_base(getpid(), "libdl", NULL),
			.remote = (uintptr_t)get_base(ctx->target, "libdl", NULL)
		};
		ctx->libdl = libdl;

		DBGPTR(libdl.local);
		DBGPTR(libdl.remote);

		void *dlopen_local = dlsym(h_libdl, "dlopen");
		off_t dlopen_offset = (off_t)PTRDIFF(dlopen_local, libdl.local);
		DBG("dlopen offset: 0x%lx", dlopen_offset);
		ctx->dlopen_offset = dlopen_offset;

		void *dlclose_local = dlsym(h_libdl, "dlclose");
		off_t dlclose_offset = (off_t)PTRDIFF(dlclose_local, libdl.local);
		DBG("dlclose offset: 0x%lx", dlclose_offset);
		ctx->dlclose_offset = dlclose_offset;

		void *dlsym_local = dlsym(h_libdl, "dlsym");
		off_t dlsym_offset = (off_t)PTRDIFF(dlsym_local, libdl.local);
		DBG("dlsym offset: 0x%lx", dlsym_offset);
		ctx->dlsym_offset = dlsym_offset;

		dlclose(h_libdl);
	}

#if defined(HAVE_LIBC_DLOPEN_MODE)
	ez_addr libc_dlopen = sym_addr(h_libc, "__libc_dlopen_mode", libc);
#elif defined(HAVE_DL_LOAD_SHARED_LIBRARY)
	ez_addr ldso = {
		.local = (uintptr_t)get_base(getpid(), "ld-uClibc", NULL),
		.remote = (uintptr_t)get_base(ctx->target, "ld-uClibc", NULL)
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

	ez_addr libc_dlopen = sym_addr(h_ldso, "_dl_load_shared_library", ldso);

	ez_addr uclibc_sym_tables = sym_addr(h_ldso, "_dl_symbol_tables", ldso);
	ez_addr uclibc_loaded_modules = sym_addr(h_ldso, "_dl_loaded_modules", ldso);

#ifdef EZ_ARCH_MIPS
	ez_addr uclibc_mips_got_reloc = sym_addr(h_ldso, "_dl_perform_mips_global_got_relocations", ldso);
	ctx->uclibc_mips_got_reloc = uclibc_mips_got_reloc;
#endif

	ez_addr uclibc_dl_fixup = sym_addr(h_ldso, "_dl_fixup", ldso);
	ctx->uclibc_sym_tables = uclibc_sym_tables;
	ctx->uclibc_loaded_modules = uclibc_loaded_modules;
	ctx->uclibc_dl_fixup = uclibc_dl_fixup;
	dlclose(h_ldso);
#endif
	ctx->libc_dlopen = libc_dlopen;

#define USE_LIBC_SYM(name) do { \
	ctx->libc_##name = sym_addr(h_libc, #name, libc); \
	DBGPTR(ctx->libc_##name.local); \
	DBGPTR(ctx->libc_##name.remote); \
} while(0)

#ifdef DEBUG
	USE_LIBC_SYM(putchar);
	USE_LIBC_SYM(puts);
#endif
	USE_LIBC_SYM(syscall);
	USE_LIBC_SYM(semop);
#undef USE_LIBC_SYM

	dlclose(h_libc);
	return 0;
}


void strPush(char **strData, struct ezinj_str str){
	memcpy(*strData, str.str, str.len);
	*strData += str.len;
}


struct injcode_bearing *prepare_bearing(struct ezinj_ctx *ctx, int argc, char *argv[]){
	size_t dyn_ptr_size = argc * sizeof(char *);
	size_t dyn_str_size = 0;

	int num_strings;

	// argc + extras
	num_strings = argc + 2;

	struct ezinj_str args[num_strings];
	int argi = 0;

#define PUSH_STRING(str) do { \
	args[argi] = ezstr_new(str); \
	dyn_str_size += args[argi].len; \
	argi++; \
} while(0)

	// libdl.so name (without path)
	PUSH_STRING(DL_LIBRARY_NAME);
	// libpthread.so name (without path)
	PUSH_STRING(PTHREAD_LIBRARY_NAME);

	// library to load
	char libName[PATH_MAX];
	if(!realpath(argv[0], libName)) {
		ERR("realpath: %s", libName);
		PERROR("realpath");
		return NULL;
	}
	PUSH_STRING(libName);

	// user arguments
	for(int i=1; i < argc; i++){
		PUSH_STRING(argv[i]);
	}
#undef PUSH_STRING

	size_t dyn_total_size = dyn_ptr_size + dyn_str_size;
	size_t mapping_size;

	if(allocate_shm(ctx, dyn_total_size, &ctx->pl, &mapping_size) != 0){
		ERR("Could not allocate shared memory");
		return NULL;
	}

	struct injcode_bearing *br = (struct injcode_bearing *)ctx->mapped_mem.local;
	if(!br){
		PERROR("malloc");
		return NULL;
	}
	br->mapping_size = mapping_size;


	br->libdl_handle = (void *)ctx->libdl.remote;
#ifdef HAVE_DL_LOAD_SHARED_LIBRARY
	br->uclibc_sym_tables = (void *)ctx->uclibc_sym_tables.remote;
	br->uclibc_dl_fixup = (void *)ctx->uclibc_dl_fixup.remote;
	br->uclibc_loaded_modules = (void *)ctx->uclibc_loaded_modules.remote;
#ifdef EZ_ARCH_MIPS
	br->uclibc_mips_got_reloc = (void *)ctx->uclibc_mips_got_reloc.remote;
#endif
#endif

	br->dlopen_offset = ctx->dlopen_offset;
	br->dlclose_offset = ctx->dlclose_offset;
	br->dlsym_offset = ctx->dlsym_offset;

#define USE_LIBC_SYM(name) do { \
	br->libc_##name = (void *)ctx->libc_##name.remote; \
	DBGPTR(br->libc_##name); \
} while(0)

	USE_LIBC_SYM(dlopen);

#ifdef DEBUG
	USE_LIBC_SYM(putchar);
	USE_LIBC_SYM(puts);
#endif

	USE_LIBC_SYM(syscall);
	USE_LIBC_SYM(semop);

#undef USE_LIBC_SYM

	br->argc = argc;
	br->dyn_size = dyn_total_size;

	strncpy(br->sym_pthread_join, "pthread_join", sizeof(br->sym_pthread_join));

	char *stringData = (char *)br + sizeof(*br) + dyn_ptr_size;
	for(int i=0; i<num_strings; i++){
		strPush(&stringData, args[i]);
	}

	// copy code
	memcpy(ctx->pl.code_start, region_pl_code.start, REGION_LENGTH(region_pl_code));

	return br;
}

int allocate_shm(struct ezinj_ctx *ctx, size_t dyn_total_size, struct ezinj_pl *layout, size_t *allocated_size){
	// br + argv
	size_t br_size = (size_t)WORDALIGN(sizeof(struct injcode_bearing) + dyn_total_size);
	// size of code payload
	size_t code_size = (size_t)WORDALIGN(REGION_LENGTH(region_pl_code));

	size_t stack_offset = br_size + code_size;
	size_t mapping_size = stack_offset + PL_STACK_SIZE;

	DBG("br_size=%zu", br_size);
	DBG("code_size=%zu", code_size);
	DBG("stack_offset=%zu", stack_offset);
	DBG("mapping_size=%zu", mapping_size);

	int shm_id, sem_id;
	if((shm_id = shmget(ctx->target, mapping_size, IPC_CREAT | IPC_EXCL | S_IRWXO)) < 0){
		PERROR("shmget");
		return 1;
	}
	INFO("SHM id: %u", shm_id);
	ctx->shm_id = shm_id;

	void *mapped_mem = shmat(shm_id, NULL, SHM_EXEC);
	if(mapped_mem == MAP_FAILED){
		PERROR("shmat");
		return 1;
	}
	ctx->mapped_mem.local = (uintptr_t)mapped_mem;

	if((sem_id = semget(ctx->target, 1, IPC_CREAT | IPC_EXCL | S_IRWXO)) < 0){
		perror("semget");
		return 1;
	}
	ctx->sem_id = sem_id;

	*allocated_size = mapping_size;

	/** prepare payload layout **/

	uint8_t *pMem = (uint8_t *)ctx->mapped_mem.local;
	layout->br_start = pMem;
	pMem += br_size;

	layout->code_start = pMem;

	pMem = (uint8_t *)ctx->mapped_mem.local + stack_offset;

	// stack is located at the end of the memory map
	layout->stack_top = (uint8_t *)ctx->mapped_mem.local + mapping_size;

	/** align stack **/

	#ifdef EZ_ARCH_AMD64
	// x64 requires a 16 bytes aligned stack for movaps
	layout->stack_top = (uint8_t *)((uintptr_t)layout->stack_top & ~ALIGNMSK(16));
	#else
	layout->stack_top = (uint8_t *)((uintptr_t)layout->stack_top & ~ALIGNMSK(sizeof(void *)));
	#endif
	return 0;
}

#define __RCALL(ctx, insn, argmask, ...) remote_call(ctx->target, ctx->syscall_stack.remote, UPTR(insn), ctx->num_wait_calls, argmask, ##__VA_ARGS__)
#define __RCALL_SC(ctx, nr, argmask, ...) __RCALL(ctx, ctx->syscall_insn.remote, argmask, nr, ##__VA_ARGS__)

#define ARGMASK(x, i) (x | (1 << (i)))
#define SC_0ARGS ARGMASK(0, 0)
#define SC_1ARGS ARGMASK(SC_0ARGS, 1)
#define SC_2ARGS ARGMASK(SC_1ARGS, 2)
#define SC_3ARGS ARGMASK(SC_2ARGS, 3)
#define SC_4ARGS ARGMASK(SC_3ARGS, 4)

// Remote System Call
#define FAILED(result) ((signed int)(result) < 0)
#define RSCALL0(ctx,nr)               __RCALL_SC(ctx,nr,SC_0ARGS)
#define RSCALL1(ctx,nr,a1)            __RCALL_SC(ctx,nr,SC_1ARGS,UPTR(a1))
#define RSCALL2(ctx,nr,a1,a2)         __RCALL_SC(ctx,nr,SC_2ARGS,UPTR(a1),UPTR(a2))
#define RSCALL3(ctx,nr,a1,a2,a3)      __RCALL_SC(ctx,nr,SC_3ARGS,UPTR(a1),UPTR(a2),UPTR(a3))
#define RSCALL4(ctx,nr,a1,a2,a3,a4)   __RCALL_SC(ctx,nr,SC_4ARGS,UPTR(a1),UPTR(a2),UPTR(a3),UPTR(a4))

void cleanup_ipc(struct ezinj_ctx *ctx){
	if(ctx->sem_id > -1){
		if(semctl(ctx->sem_id, IPC_RMID, 0) < 0){
			PERROR("semctl (IPC_RMID)");
		} else {
			ctx->sem_id = -1;
		}
	}
	if(ctx->mapped_mem.local != 0){
		if(shmdt((void *)ctx->mapped_mem.local) < 0){
			PERROR("shmdt");
		} else {
			ctx->mapped_mem.local = 0;
		}
	}
	if(ctx->shm_id > -1){
		if(shmctl(ctx->shm_id, IPC_RMID, NULL) < 0){
			PERROR("shmctl (IPC_RMID)");
		} else {
			ctx->shm_id = -1;
		}
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
	uintptr_t codeBase = get_code_base(ctx->target);
	if(codeBase == 0){
		ERR("Could not obtain code base");
		return 1;
	}

	signal(SIGINT, sigint_handler);

	// allocate bearing on shared memory
	struct injcode_bearing *br = prepare_bearing(ctx, argc, argv);
	if(br == NULL){
		return -1;
	}

	size_t dataLength = ROUND_UP(
		REGION_LENGTH(region_sc_insn),
		sizeof(uintptr_t)
	);

	DBG("dataLength: %zu", dataLength);
	uint8_t dataBak[dataLength];
	{ //backup and replace ELF header
		uintptr_t *pWordsIn = (uintptr_t *)&dataBak;
		uintptr_t *pWordsOut = (uintptr_t *)region_sc_insn.start;
		for(unsigned int i=0; i<dataLength; i+=sizeof(uintptr_t), pWordsIn++, pWordsOut++){
			*pWordsIn = (uintptr_t)ptrace(PTRACE_PEEKTEXT, ctx->target, codeBase + i, 0);
			ptrace(PTRACE_POKETEXT, ctx->target, codeBase + i, *pWordsOut);
		}
		ctx->syscall_insn.remote = codeBase;
#ifdef EZ_ARCH_MIPS
		// skip syscall instruction and apply stack offset (see note about sys_ipc)
		ctx->syscall_stack.remote = codeBase + 4 - 16;
#endif
	}

	// wait for a single syscall
	ctx->num_wait_calls = 1;

	/* Verify that remote_call works correctly */
	pid_t remote_pid = (pid_t)RSCALL0(ctx, __NR_getpid);
	if(remote_pid != ctx->target)
	{
		ERR("Remote syscall returned incorrect result!");
		ERR("Expected: %u, actual: %u", ctx->target, remote_pid);
		return 1;
	}

	int err = 1;
	do {

#ifdef HAVE_SHM_SYSCALLS
		uintptr_t remote_shm_ptr = CHECK(RSCALL3(ctx, __NR_shmat, ctx->shm_id, NULL, SHM_EXEC));
		INFO("shmat => %p", (void *)remote_shm_ptr);
#else

		CHECK(RSCALL3(ctx, __NR_mprotect, codeBase, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC));
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
		CHECK(RSCALL4(ctx, __NR_ipc, IPCCALL(0, SHMAT), ctx->shm_id, SHM_EXEC, codeBase + 4));
		uintptr_t remote_shm_ptr = ptrace(PTRACE_PEEKTEXT, ctx->target, codeBase + 4);
		DBGPTR(remote_shm_ptr);
		CHECK(RSCALL3(ctx, __NR_mprotect, codeBase, getpagesize(), PROT_READ | PROT_EXEC));
#endif
		if(remote_shm_ptr == (uintptr_t)MAP_FAILED || remote_shm_ptr == 0){
			ERR("Remote shmat failed: %p", (void *)remote_shm_ptr);
			break;
		}


		ctx->mapped_mem.remote = remote_shm_ptr;

		struct ezinj_pl *pl = &ctx->pl;

		#define PL_REMOTE(pl_addr) \
			UPTR(remote_shm_ptr + PTRDIFF(pl_addr, ctx->mapped_mem.local))

		#define PL_REMOTE_CODE(addr) \
			PL_REMOTE(pl->code_start) + PTRDIFF(addr, &injected_code_start)


		// clone entry
		uintptr_t remote_clone_entry = PL_REMOTE_CODE(&injected_clone_entry);

		// stack base
		uintptr_t *target_sp = (uintptr_t *)pl->stack_top;

		// reserve space for 3 arguments at the top of the initial stack
		// force stack to snap to the lowest 16 bytes, or it will crash on x64
		uintptr_t *stack_argv = (uintptr_t *)(
			((uintptr_t)target_sp - (sizeof(uintptr_t) * 2))
		);

		DBGPTR(target_sp);

		// push clone arguments
		stack_argv[0] = PL_REMOTE(pl->br_start);
		stack_argv[1] = PL_REMOTE_CODE(&injected_clone_proper);

		DBGPTR(stack_argv[0]);
		DBGPTR(stack_argv[1]);

		DBGPTR(remote_clone_entry);

		if(msync((void *)ctx->mapped_mem.local, SIZEOF_BR(*br), MS_SYNC|MS_INVALIDATE) < 0){
			PERROR("msync");
		}
		CHECK(RSCALL3(ctx, __NR_madvise, remote_shm_ptr, SIZEOF_BR(*br), MADV_SEQUENTIAL | MADV_WILLNEED));
		// some broken kernels don't actually do this immediately (cache issue?)
#if defined(EZ_ARCH_ARM) || defined(EZ_ARCH_MIPS)
		usleep(50000);
#endif

		// switch to SIGSTOP wait mode
		ctx->num_wait_calls = 0;
		ctx->syscall_stack.remote = (uintptr_t)PL_REMOTE(stack_argv); // stack is at the bottom of arguments (pop will move it up)

		CHECK(__RCALL(ctx, remote_clone_entry, 0));

		ctx->num_wait_calls = 1;
		ctx->syscall_stack.remote = 0;

#ifdef HAVE_SHM_SYSCALLS
		CHECK(RSCALL1(ctx, __NR_shmdt, remote_shm_ptr));
#else
		// skip syscall instruction and apply stack offset (see note about sys_ipc)
		ctx->syscall_stack.remote = codeBase + 4 - 16;
		CHECK(RSCALL4(ctx, __NR_ipc, IPCCALL(0, SHMDT), 0, 0, codeBase + 4));
#endif

		{ //restore ELF header
			uintptr_t *pWordsOut = (uintptr_t *)&dataBak;
			for(unsigned int i=0; i<dataLength; i+=sizeof(uintptr_t), pWordsOut++){
				ptrace(PTRACE_POKETEXT, ctx->target, codeBase + i, *pWordsOut);
			}
		}

		err = 0;
	} while(0);

	return err;
}

int main(int argc, char *argv[]){
	if(argc < 3) {
		ERR("Usage: %s pid library-to-inject", argv[0]);
		return 1;
	}

	const char *argPid = argv[1];
	pid_t target = atoi(argPid);

	if(ptrace(PTRACE_ATTACH, target, 0, 0) < 0){
		PERROR("ptrace attach");
		return 1;
	}

	int err = 0;
	/* Wait for attached process to stop */
	{
		int status = 0;
		for(;;){
			waitpid(target, &status, 0);
			if(WIFSTOPPED(status)){
				int stopsig = WSTOPSIG(status);
				if(!IS_IGNORED_SIG(stopsig)){
					break;
				}
				INFO("Skipping signal %u", stopsig);
				CHECK(ptrace(PTRACE_CONT, target, 0, stopsig));
			}
		}
	}

	if(ptrace(PTRACE_SETOPTIONS, target, 0, PTRACE_O_TRACESYSGOOD) < 0){
		PERROR("ptrace setoptions");
		return 1;
	}

	ctx.target = target;
	if(libc_init(&ctx) != 0){
		return 1;
	}

	err = ezinject_main(&ctx, argc - 2, &argv[2]);

	CHECK(ptrace(PTRACE_DETACH, target, 0, 0));

	if(err != 0){
		return err;
	}

	cleanup_ipc(&ctx);
	return err;
}
