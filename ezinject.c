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

#include "config.h"

#ifdef HAVE_SYS_SHM_H
#include <sys/shm.h>
#endif

#include <sys/ipc.h>
#include <sys/stat.h>

#if defined(EZ_TARGET_LINUX) && !defined(HAVE_SHM_SYSCALLS)
#include <asm-generic/ipc.h>
#endif

#ifdef EZ_TARGET_FREEBSD
#include <sys/sysproto.h>
#endif

#include "util.h"
#include "ezinject.h"
#include "ezinject_compat.h"
#include "ezinject_common.h"
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
int resolve_libc_symbols(struct ezinj_ctx *ctx);

/**
 * Prepares the target process for a call invocation with syscall convention
 * NOTE: this function can be used to call anything, not just system calls
 * 
 * @param[in]  orig_ctx	 the current process context
 * @param[out] new_ctx   the new process context
 * @param[in]  call      call arguments and options
 **/
void setregs_syscall(
	regs_t *orig_ctx,
	regs_t *new_ctx,
	struct call_req call
){
	struct sc_req sc = call.syscall;

	REG(*new_ctx, REG_PC) = call.insn_addr;

	if(SC_HAS_ARG(sc, 0)){
		REG(*new_ctx, REG_NR)   = sc.argv[0];
	#if defined(EZ_TARGET_FREEBSD) && defined(EZ_ARCH_I386)
		uintptr_t stack[8];
		int num_words = 0;
		for(int i=1; i<=6; i++){
			if(SC_HAS_ARG(sc, i)){
				// push argument
				stack[i] = sc.argv[i];
				DBG("push %d, %p", i, (void *)sc.argv[i]);
				num_words++;
			}
		}
		// if we have pushed any argument, account for the stack frame offsets
		if(num_words > 0){
			// dummy saved EIP
			stack[0] = 0; num_words++;

			// not sure why this is needed but it doesn't work without.
			// padding?
			stack[num_words++] = 0;

			sc.frame_size = (sizeof(uintptr_t) * num_words);
			sc.frame_bottom = REG(*orig_ctx, REG_SP) - sc.frame_size;
			REG(*new_ctx, REG_SP) = sc.frame_bottom;

			// FIXME: global variable
			// save stack for extra safety (we don't know what the process was doing when we interrupted it)
			remote_read(&ctx, &sc.saved_stack, sc.frame_bottom, sizeof(sc.saved_stack));
			size_t written = remote_write(&ctx, sc.frame_bottom, &stack, sc.frame_size);
			DBG("written stack frame, %zu bytes", written);
		}
	#else
		REG(*new_ctx, REG_ARG1) = sc.argv[1];
		REG(*new_ctx, REG_ARG2) = sc.argv[2];
		REG(*new_ctx, REG_ARG3) = sc.argv[3];
		REG(*new_ctx, REG_ARG4) = sc.argv[4];
		#ifdef REG_ARG5
		REG(*new_ctx, REG_ARG5) = sc.argv[5];
		#endif
		#ifdef REG_ARG6
		REG(*new_ctx, REG_ARG6) = sc.argv[6];
		#endif
	#endif

		DBG("remote_call(%u)", (unsigned int)sc.argv[0]);
	}

	#ifdef USE_ARM_THUMB
	REG(*new_ctx, ARM_cpsr) = REG(*new_ctx, ARM_cpsr) | PSR_T_BIT;
	#endif

	if(call.stack_addr != 0){
		DBGPTR(call.stack_addr);
		REG(*new_ctx, REG_SP) = call.stack_addr;
	}

#if defined(EZ_ARCH_I386) && !defined(EZ_TARGET_FREEBSD)
	//ebp must point to valid stack
	REG(*new_ctx, REG_ARG6) = REG(*orig_ctx, REG_SP);
#else
	UNUSED(orig_ctx);
#endif

}


void remote_call_setup(pid_t target, struct call_req call, regs_t *orig_ctx, regs_t *new_ctx){
	memset(orig_ctx, 0x00, sizeof(*orig_ctx));

	remote_getregs(target, orig_ctx);
	memcpy(new_ctx, orig_ctx, sizeof(*orig_ctx));

	setregs_syscall(orig_ctx, new_ctx, call);
	remote_setregs(target, new_ctx);
}

#if defined(EZ_TARGET_LINUX)
#define SC_EVENT_STATUS (SIGTRAP | 0x80)
#elif defined(EZ_TARGET_FREEBSD)
#define SC_EVENT_STATUS SIGTRAP
#endif

#ifdef EZ_TARGET_FREEBSD
static int lwp_ensure_state(pid_t target, unsigned int flags){
	struct ptrace_lwpinfo info;
	if (ptrace(PT_LWPINFO, target, (caddr_t)&info, sizeof(info)) < 0){
		return -1;
	}

	if((info.pl_flags & flags) != 0){
		return 0; //good state
	}
	return -1;
}
#endif

#define ARGMASK(x, i) (x | (1 << (i)))
#define SC_0ARGS ARGMASK(0, 0)
#define SC_1ARGS ARGMASK(SC_0ARGS, 1)
#define SC_2ARGS ARGMASK(SC_1ARGS, 2)
#define SC_3ARGS ARGMASK(SC_2ARGS, 3)
#define SC_4ARGS ARGMASK(SC_3ARGS, 4)
#define SC_5ARGS ARGMASK(SC_4ARGS, 5)
#define SC_6ARGS ARGMASK(SC_5ARGS, 6)

uintptr_t remote_call_common(pid_t target, struct call_req call){
	regs_t orig_ctx, new_ctx;
	remote_call_setup(target, call, &orig_ctx, &new_ctx);

	uintptr_t sc_ret;

	int status;
	for(int i=0; i<call.num_wait_calls; i++){
		int rc;
		do {
			if(remote_syscall_step(target) < 0){
				PERROR("ptrace");
				return -1;
			}
			status = remote_wait(target);
			if((rc=WSTOPSIG(status)) != SC_EVENT_STATUS){
				ERR("remote_wait: %s", strsignal(rc));
				return -1;
			}

			#if defined(EZ_TARGET_FREEBSD)
			if(lwp_ensure_state(target, PL_FLAG_SCE) != 0){
				ERR("Not in syscall entry");
				return -1;
			}
			#endif
			remote_syscall_step(target);

			status = remote_wait(target);
			if((rc=WSTOPSIG(status)) != SC_EVENT_STATUS){
				ERR("remote_wait: %s", strsignal(rc));
				return -1;
			}

			#ifdef EZ_TARGET_FREEBSD
			if(lwp_ensure_state(target, PL_FLAG_SCX) != 0){
				ERR("Not in syscall exit");
				return -1;
			}
			#endif

			#if 0//def EZ_TARGET_FREEBSD
			struct ptrace_sc_ret fbsd_sc_ret;
			if(ptrace(PT_GET_SC_RET, target, (caddr_t)&fbsd_sc_ret, sizeof(fbsd_sc_ret)) < 0){
				PERROR("ptrace");
				return -1;
			}
			DBGPTR(fbsd_sc_ret.sr_retval[0]);
			DBGPTR(fbsd_sc_ret.sr_retval[1]);
			DBGPTR(fbsd_sc_ret.sr_error);
			sc_ret = fbsd_sc_ret.sr_retval[0];
			#else
			// get syscall return value
			if(remote_getregs(target, &new_ctx) < 0){ /* Get return value */
				PERROR("ptrace");
				return -1;
			}
			sc_ret = REG(new_ctx, REG_RET);
			#endif

			DBG("[RET] = %zu", sc_ret);

			if((signed int)sc_ret == -EINTR){
				remote_call_setup(target, call, &orig_ctx, &new_ctx);
			}
		} while((signed int)sc_ret == -EINTR);
	}

	if(call.num_wait_calls == 0){
		// disable syscall tracing
		remote_syscall_trace_enable(target, 0);
		int stopsig = 0;
		do {

			DBG("continuing...");
			// pass signal to child
			if(remote_continue(target, stopsig) < 0){
				PERROR("ptrace");
				return -1;
			}

			if(ctx.pl_debug){
				kill(target, SIGSTOP);
			}

			// wait for the children to stop
			status = remote_wait(target);

			stopsig = WSTOPSIG(status);
			DBG("got signal: %d (%s)", stopsig, strsignal(stopsig));

			/**
			 * if we're debugging payload
			 * we break early as the target should
			 * now be in an endless loop
			 **/
			if(ctx.pl_debug){
				return -1;
			}
		} while(IS_IGNORED_SIG(stopsig));

		if(remote_getregs(target, &new_ctx) < 0){
			PERROR("ptrace");
			return -1;
		}

		if(stopsig != SIGSTOP){
			ERR("Unexpected signal (expected SIGSTOP)");

			regs_t tmp;
			remote_getregs(target, &tmp);
			DBG("CRASH @ %p (offset: %i)",
				(void *)REG(tmp, REG_PC),
				(signed int)(REG(tmp, REG_PC) - call.insn_addr)
			);
		}

		if(stopsig == SIGTRAP || stopsig == SIGSEGV){
			// child raised a debug event
			// this is a debug condition, so do a hard exit
			// $TODO: do it nicer
			remote_detach(target);
			exit(0);
			return -1;
		}
	}

	#ifdef EZ_TARGET_FREEBSD
	if(call.syscall.argmask > SC_0ARGS){
		// FIXME: global variable
		// restore overwritten stack
		DBG("restoring stack frame");
		remote_write(&ctx,
			call.syscall.frame_bottom,
			&call.syscall.saved_stack,
			call.syscall.frame_size
		);
	}
	#endif

	remote_setregs(target, &orig_ctx);

#ifdef DEBUG
	DBG("PC: %p => %p",
		(void *)call.insn_addr,
		(void *)((uintptr_t)REG(new_ctx, REG_PC)));
#endif

	return sc_ret;
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
		.remote = (sym_addr == 0) ? 0 : EZ_REMOTE(lib, sym_addr)
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

	if(resolve_libc_symbols(ctx) != 0){
		return 1;
	}

#define USE_LIBC_SYM(name) do { \
	ctx->libc_##name = sym_addr(h_libc, #name, libc); \
	DBGPTR(ctx->libc_##name.local); \
	DBGPTR(ctx->libc_##name.remote); \
} while(0)

#ifdef DEBUG
	USE_LIBC_SYM(printf);
#endif

	USE_LIBC_SYM(syscall);
#undef USE_LIBC_SYM

	dlclose(h_libc);
	return 0;
}

/**
 * Marshals the string @str into @strData, advancing the data pointer as needed
 * 
 * @param[in]  str
 * 	structure describing the string to copy
 * @param[out] strData  
 * 	pointer (pass by reference) to a block of memory where the string will be copied
 * 	the pointer will be incremented by the number of bytes copied
 **/
void strPush(char **strData, struct ezinj_str str){
	// write the number of bytes we need to skip to get to the next string
	*(unsigned int *)(*strData) = sizeof(unsigned int) + str.len;
	*strData += sizeof(unsigned int);

	// write the string itself
	memcpy(*strData, str.str, str.len);
	*strData += str.len;
}


struct injcode_bearing *prepare_bearing(struct ezinj_ctx *ctx, int argc, char *argv[]){
	size_t dyn_ptr_size = argc * sizeof(char *);
	size_t dyn_str_size = 0;

	int num_strings;

	// argc + extras
	num_strings = argc + 10;

	struct ezinj_str args[num_strings];
	int argi = 0;
	off_t argv_offset = 0;

#define PUSH_STRING(str) do { \
	args[argi] = ezstr_new(str); \
	dyn_str_size += args[argi].len + sizeof(unsigned int); \
	argi++; \
} while(0)

	// libdl.so name (without path)
	PUSH_STRING(DL_LIBRARY_NAME);
	// libpthread.so name (without path)
	PUSH_STRING(PTHREAD_LIBRARY_NAME);

	PUSH_STRING("dlerror");
	PUSH_STRING("pthread_mutex_init");
	PUSH_STRING("pthread_mutex_lock");
	PUSH_STRING("pthread_mutex_unlock");
	PUSH_STRING("pthread_cond_init");
	PUSH_STRING("pthread_cond_wait");
	PUSH_STRING("pthread_join");
	PUSH_STRING("crt_init");

	// library to load
	char libName[PATH_MAX];
	if(!realpath(argv[0], libName)) {
		ERR("realpath: %s", libName);
		PERROR("realpath");
		return NULL;
	}

	argv_offset = dyn_str_size;
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
	memset(br, 0x00, sizeof(*br));

	if(!br){
		PERROR("malloc");
		return NULL;
	}
	br->mapping_size = mapping_size;

	br->pl_debug = ctx->pl_debug;

	br->libdl_handle = (void *)ctx->libdl.remote;
#if defined(HAVE_DL_LOAD_SHARED_LIBRARY)
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
	USE_LIBC_SYM(printf);
#endif

	USE_LIBC_SYM(syscall);
#undef USE_LIBC_SYM

	br->argc = argc;
	br->dyn_size = dyn_total_size;
	br->num_strings = num_strings;
	br->argv_offset = argv_offset;

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

	#ifdef USE_ARM_THUMB
	code_size |= 1;
	#endif

	size_t stack_offset = br_size + code_size;
	size_t mapping_size = stack_offset + PL_STACK_SIZE;

	DBG("br_size=%zu", br_size);
	DBG("code_size=%zu", code_size);
	DBG("stack_offset=%zu", stack_offset);
	DBG("mapping_size=%zu", mapping_size);

	#ifdef USE_SHM
	int shm_id;
	if((shm_id = shmget(ctx->target, mapping_size, IPC_CREAT | IPC_EXCL | S_IRWXU | S_IRWXG | S_IRWXO)) < 0){
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
	#else
	void *mapped_mem = calloc(1, mapping_size);
	#endif

	ctx->mapped_mem.local = (uintptr_t)mapped_mem;

	*allocated_size = mapping_size;

	/** prepare payload layout **/

	uint8_t *pMem = (uint8_t *)ctx->mapped_mem.local;
	layout->br_start = pMem;
	pMem += br_size;

	#ifdef USE_ARM_THUMB
	pMem = (void *)(UPTR(pMem) | 1);
	#endif

	layout->code_start = pMem;

	// stack is located at the end of the memory map
	layout->stack_top = (uint8_t *)ctx->mapped_mem.local + mapping_size;

	/** align stack **/

	#if defined(EZ_ARCH_AMD64) || defined(EZ_ARCH_ARM64)
	// x64 requires a 16 bytes aligned stack for movaps
	// force stack to snap to the lowest 16 bytes, or it will crash on x64
	layout->stack_top = (uint8_t *)((uintptr_t)layout->stack_top & ~ALIGNMSK(16));
	#else
	layout->stack_top = (uint8_t *)((uintptr_t)layout->stack_top & ~ALIGNMSK(sizeof(void *)));
	#endif
	return 0;
}

#define __RCALL(ctx, insn, argmask, ...) remote_call(ctx->target, ctx->syscall_stack.remote, UPTR(insn), ctx->num_wait_calls, argmask, ##__VA_ARGS__)
#define __RCALL_SC(ctx, nr, argmask, ...) __RCALL(ctx, ctx->syscall_insn.remote, argmask, nr, ##__VA_ARGS__)

// Remote System Call
#define FAILED(result) ((signed int)(result) < 0)
#define RSCALL0(ctx,nr)               __RCALL_SC(ctx,nr,SC_0ARGS)
#define RSCALL1(ctx,nr,a1)            __RCALL_SC(ctx,nr,SC_1ARGS,UPTR(a1))
#define RSCALL2(ctx,nr,a1,a2)         __RCALL_SC(ctx,nr,SC_2ARGS,UPTR(a1),UPTR(a2))
#define RSCALL3(ctx,nr,a1,a2,a3)      __RCALL_SC(ctx,nr,SC_3ARGS,UPTR(a1),UPTR(a2),UPTR(a3))
#define RSCALL4(ctx,nr,a1,a2,a3,a4)   __RCALL_SC(ctx,nr,SC_4ARGS,UPTR(a1),UPTR(a2),UPTR(a3),UPTR(a4))
#define RSCALL5(ctx,nr,a1,a2,a3,a4,a5) __RCALL_SC(ctx,nr,SC_5ARGS,UPTR(a1),UPTR(a2),UPTR(a3),UPTR(a4),UPTR(a5))
#define RSCALL6(ctx,nr,a1,a2,a3,a4,a5,a6) __RCALL_SC(ctx,nr,SC_6ARGS,UPTR(a1),UPTR(a2),UPTR(a3),UPTR(a4),UPTR(a5),UPTR(a6))

void cleanup_mem(struct ezinj_ctx *ctx){
	#ifdef USE_SHM
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
	#else
	free((void *)ctx->mapped_mem.local);
	#endif
}

void sigint_handler(int signum){
	UNUSED(signum);
	cleanup_mem(&ctx);
}

#ifdef EZ_TARGET_ANDROID
#include "ezinject_android.c"
#endif

uintptr_t remote_shmat(struct ezinj_ctx *ctx, key_t shm_id, void *shmaddr, int shmflg){
	uintptr_t remote_shm_ptr = 0;
	#if defined(EZ_TARGET_LINUX)
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
		DBGPTR(remote_shm_ptr);
		CHECK(RSCALL3(ctx, __NR_mprotect, ctx->target_codebase, getpagesize(), PROT_READ | PROT_EXEC));
	#endif
	#elif defined(EZ_TARGET_FREEBSD)
	remote_shm_ptr = CHECK(RSCALL3(ctx, SYS_shmat, shm_id, shmaddr, shmflg));
	#endif
	INFO("shmat => %p", (void *)remote_shm_ptr);
	return remote_shm_ptr;
}

int remote_shmdt(struct ezinj_ctx *ctx, uintptr_t remote_shmaddr){
	int result = -1;
	#if defined(EZ_TARGET_LINUX)
	#ifdef HAVE_SHM_SYSCALLS
		result = (int) CHECK(RSCALL1(ctx, __NR_shmdt, remote_shmaddr));
	#else
		// skip syscall instruction and apply stack offset (see note about sys_ipc)
		ctx->syscall_stack.remote = ctx->target_codebase + 4 - 16;
		result = (int) CHECK(RSCALL4(ctx, __NR_ipc, IPCCALL(0, SHMDT), 0, 0, ctx->target_codebase + 4));
	#endif
	#elif defined(EZ_TARGET_FREEBSD)
		result = (int) CHECK(RSCALL1(ctx, SYS_shmdt, remote_shmaddr));
	#endif
	return result;
}

#if defined(EZ_TARGET_LINUX)
void print_maps(){
	pid_t pid = syscall(__NR_getpid);
	char *path;
	asprintf(&path, "/proc/%u/maps", pid);
	do {
		FILE *fh = fopen(path, "r");
		if(!fh){
			return;
		}
		
		char line[256];
		while(!feof(fh)){
			fgets(line, sizeof(line), fh);
			fputs(line, stdout);
		}
		fclose(fh);
	} while(0);
	free(path);
}
#else
void print_maps(){}
#endif

int ezinject_main(
	struct ezinj_ctx *ctx,
	int argc, char *argv[]
){
	print_maps();
	fflush(stdout);

	uintptr_t codeBase = (uintptr_t) get_base(ctx->target, NULL, NULL);
	if(codeBase == 0){
		ERR("Could not obtain code base");
		return 1;
	}
	DBGPTR(codeBase);
	ctx->target_codebase = codeBase;

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
	//backup and replace ELF header
	remote_read(ctx, &dataBak, codeBase, dataLength);
	remote_write(ctx, codeBase, region_sc_insn.start, dataLength);
	ctx->syscall_insn.remote = codeBase;

#ifdef EZ_ARCH_MIPS
	// skip syscall instruction and apply stack offset (see note about sys_ipc)
	ctx->syscall_stack.remote = codeBase + 4 - 16;
#endif

	// wait for a single syscall
	ctx->num_wait_calls = 1;

	/* Verify that remote_call works correctly */
	#if defined(EZ_TARGET_LINUX)
	pid_t remote_pid = (pid_t)RSCALL0(ctx, __NR_getpid);
	#elif defined(EZ_TARGET_FREEBSD)
	pid_t remote_pid = (pid_t)RSCALL0(ctx, SYS_getpid);
	#endif
	if(remote_pid != ctx->target)
	{
		ERR("Remote syscall returned incorrect result!");
		ERR("Expected: %u, actual: %u", ctx->target, remote_pid);
		return 1;
	}

	int err = 1;
	do {
		uintptr_t remote_shm_ptr = 0;
		#if defined(EZ_TARGET_ANDROID) && defined(USE_ANDROID_ASHMEM)
		remote_shm_ptr = remote_shmat_android(ctx, br->mapping_size);
		#elif defined(EZ_TARGET_LINUX)
		remote_shm_ptr = remote_shmat(ctx, ctx->shm_id, NULL, SHM_EXEC);
		#elif defined(EZ_TARGET_FREEBSD)
		// FreeBSD doesn't allow executable shared memory
		remote_shm_ptr = RSCALL6(ctx, SYS_mmap,
			NULL, br->mapping_size,
			PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_ANONYMOUS, -1, 0
		);
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


		// trampoline entry
		uintptr_t remote_trampoline_entry = PL_REMOTE_CODE(&trampoline_entry);

		// stack base
		uintptr_t *target_sp = (uintptr_t *)pl->stack_top;

		// reserve space for 2 arguments at the top of the initial stack
		uintptr_t *stack_argv = (uintptr_t *)(
			((uintptr_t)target_sp - (sizeof(uintptr_t) * 2))
		);

		DBGPTR(target_sp);

		// push clone arguments
		stack_argv[0] = PL_REMOTE(pl->br_start);
		stack_argv[1] = PL_REMOTE_CODE(&injected_fn);

		DBGPTR(stack_argv[0]);
		DBGPTR(stack_argv[1]);

		DBGPTR(remote_trampoline_entry);

		#ifdef __GNUC__
		{
			void *flush_start = br;
			void *flush_end = (void *)(UPTR(br) + br->mapping_size);
			__builtin___clear_cache(flush_start, flush_end);
		}
		#else
		usleep(50000);
		#endif

		
		#ifdef EZ_TARGET_FREEBSD
		remote_write(ctx, ctx->mapped_mem.remote, ctx->mapped_mem.local, br->mapping_size);
		#endif

		// switch to SIGSTOP wait mode
		ctx->num_wait_calls = 0;
		ctx->syscall_stack.remote = (uintptr_t)PL_REMOTE(stack_argv); // stack is at the bottom of arguments (pop will move it up)

		CHECK(__RCALL(ctx, remote_trampoline_entry, 0));

		/**
		 * if payload debugging is on, skip any cleanup
		 **/
		if(ctx->pl_debug){
			return -1;
		}

		ctx->num_wait_calls = 1;
		ctx->syscall_stack.remote = 0;

		remote_shmdt(ctx, remote_shm_ptr);

		//restore ELF header
		remote_write(ctx, codeBase, &dataBak, dataLength);

		err = 0;
	} while(0);

	return err;
}

int main(int argc, char *argv[]){
	if(argc < 3) {
		ERR("Usage: %s pid library-to-inject", argv[0]);
		return 1;
	}

	memset(&ctx, 0x00, sizeof(ctx));

	{
		int c;
		while ((c = getopt (argc, argv, "d")) != -1){
			switch(c){
				case 'd':
					WARN("payload debugging enabled, the target **WILL** freeze");
					ctx.pl_debug = 1;
					break;
			}
		}
	}

	const char *argPid = argv[optind++];
	pid_t target = atoi(argPid);

	if(remote_attach(target) < 0){
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
				CHECK(remote_continue(target, stopsig));
			}
		}
	}

#if defined(EZ_TARGET_LINUX)
	if(ptrace(PTRACE_SETOPTIONS, target, 0, PTRACE_O_TRACESYSGOOD) < 0){
		PERROR("ptrace setoptions");
		return 1;
	}
#endif

	ctx.target = target;
	if(libc_init(&ctx) != 0){
		return 1;
	}

	err = ezinject_main(&ctx, argc - optind, &argv[optind]);

	CHECK(remote_detach(target));

	/**
	 * skip IPC cleanup if we encountered any error
	 * (payload debugging counts as failure)
	 **/
	if(err != 0){
		if(ctx.pl_debug){
			INFO("You may now attach with gdb for payload debugging");
			#ifdef USE_ANDROID_ASHMEM
			INFO("Press Enter to quit");
			getchar();
			#endif
		}
		return err;
	}

	cleanup_mem(&ctx);
	return err;
}
