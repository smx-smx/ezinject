#define _GNU_SOURCE
#define EZINJECT_INJCODE

#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sched.h>
#include <pthread.h>
#include <sys/stat.h>

#include "config.h"

#ifdef EZ_TARGET_POSIX
#include <signal.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#endif

#if defined(EZ_TARGET_LINUX)
#include <sys/prctl.h>
#endif

#include "ezinject_compat.h"
#include "ezinject_common.h"
#include "ezinject_arch.h"
#include "ezinject_injcode.h"

#ifdef EZ_TARGET_WINDOWS
// for BYTE_ORDER
#include <sys/param.h>
#endif

#define UNUSED(x) (void)(x)

#ifdef HAVE_LIBC_DLOPEN_MODE
#define __RTLD_DLOPEN 0x80000000 /* glibc internal */
#endif

#ifdef EZ_TARGET_POSIX
intptr_t SCAPI injected_sc0(volatile struct injcode_call *sc){
	return sc->libc_syscall(sc->argv[0]);
}
intptr_t SCAPI injected_sc1(volatile struct injcode_call *sc){
	return sc->libc_syscall(
		sc->argv[0], sc->argv[1]
	);
}
intptr_t SCAPI injected_sc2(volatile struct injcode_call *sc){
	return sc->libc_syscall(
		sc->argv[0], sc->argv[1],
		sc->argv[2]
	);
}
intptr_t SCAPI injected_sc3(volatile struct injcode_call *sc){
	return sc->libc_syscall(
		sc->argv[0], sc->argv[1],
		sc->argv[2], sc->argv[3]
	);
}
intptr_t SCAPI injected_sc4(volatile struct injcode_call *sc){
	return sc->libc_syscall(
		sc->argv[0], sc->argv[1],
		sc->argv[2], sc->argv[3],
		sc->argv[4]
	);
}
intptr_t SCAPI injected_sc5(volatile struct injcode_call *sc){
	return sc->libc_syscall(
		sc->argv[0], sc->argv[1],
		sc->argv[2], sc->argv[3],
		sc->argv[4], sc->argv[5]
	);
}
intptr_t SCAPI injected_sc6(volatile struct injcode_call *sc){
	return sc->libc_syscall(
		sc->argv[0], sc->argv[1],
		sc->argv[2], sc->argv[3],
		sc->argv[4], sc->argv[5],
		sc->argv[6]
	);
}
#endif

/**
 * On ARM/Linux + glibc, making system calls and writing their results in the same function
 * seems to cause a very subtle stack corruption bug that ultimately causes dlopen/dlsym to segfault
 * to work around that, we use a wrapper so that the system call is executed in a different subroutine
 * than the one setting the result.
 **/
void SCAPI injected_sc_wrapper(volatile struct injcode_call *args){
	args->result = args->wrapper.target(args);
#if defined(EZ_TARGET_POSIX)
	args->libc_syscall(__NR_kill,
		args->libc_syscall(__NR_getpid),
		SIGTRAP
	);
	while(1);
#elif defined(EZ_TARGET_WINDOWS)
	asm volatile("int $3\n");
#else
#error "Unsupported target"
#endif
}

//#define PL_EARLYDEBUG

void PLAPI trampoline(){
	/**
	 * if the process was blocked in a system call
	 * the program counter will be subtracted by sizeof(instruction)
	 * upon detach
	 * https://stackoverflow.com/a/38009680/11782802
	 *
	 * this is a problem because we risk running the prologue of this function
	 * and cause a stack misalignment
	 * we must emit NOPs that are at least as big as the syscall instruction
	 * 
	 **/
	asm volatile("nop\n");
	asm volatile("nop\n");
	asm volatile("nop\n");
	asm volatile("nop\n");

	EMIT_LABEL("trampoline_entry");

	#ifdef PL_EARLYDEBUG
	asm volatile(JMP_INSN " .");
	#endif

	register volatile struct injcode_call *args = NULL;
	register uintptr_t (*target)(volatile struct injcode_call *) = NULL;
	POP_PARAMS(args, target);
	target(args);

	asm volatile(JMP_INSN " .");
	EMIT_LABEL("trampoline_exit");
}

INLINE uint64_t str64(uint64_t x){
	#ifndef BYTE_ORDER
		#error "BYTE_ORDER not defined"
	#endif
	#if BYTE_ORDER == BIG_ENDIAN
		return x;
	#elif BYTE_ORDER == LITTLE_ENDIAN
		return __builtin_bswap64(x);
	#else
		#error "Unknown endianness"
	#endif
}

#include "ezinject_injcode_common.c"

#if defined(EZ_TARGET_POSIX)
#include "ezinject_injcode_posix_common.c"
#elif defined(EZ_TARGET_WINDOWS)
#include "ezinject_injcode_windows_common.c"
#endif

INLINE void inj_dbgptr(struct injcode_bearing *br, void *ptr){
	char buf[sizeof(uintptr_t) + 1];
	itoa16((uintptr_t)ptr, buf);
	inj_puts(br, buf);
}

struct injcode_ctx {
	struct injcode_bearing *br;

	struct dl_api libdl;
	struct thread_api libthread;
	char *stbl;
	
	char *libdl_name;
	char *libpthread_name;
	char *userlib_name;

	/** handle to the library providing dynamic linkage **/
	void *h_libdl;
	/** handle to the library providing threads **/
	void *h_libthread;
};

#include "ezinject_injcode_util.c"

INLINE intptr_t fetch_sym(
	struct injcode_ctx *ctx,
	void *handle, void **sym
){
	char *sym_name;
	// advances stbl in ctx
	STRTBL_FETCH(ctx->stbl, sym_name);
#ifdef DEBUG
	inj_puts(ctx->br, sym_name);
#endif
	inj_cacheflush(ctx->br, &sym_name, (void *)(UPTR(&sym_name) + sizeof(sym_name)));
	*sym = ctx->libdl.dlsym(handle, sym_name);
	if(*sym == NULL){
		inj_dchar(ctx->br, '!');
		inj_dchar(ctx->br, 's');
		inj_puts(ctx->br, sym_name);
		return -1;
	}
	return 0;
}

#ifdef EZ_TARGET_POSIX
#include "ezinject_injcode_posix.c"
#endif

#if defined(EZ_TARGET_LINUX) && !defined(EZ_TARGET_ANDROID)
	#if defined(HAVE_LIBC_DLOPEN_MODE)
		#include "ezinject_injcode_glibc.c"
	#elif defined(HAVE_DL_LOAD_SHARED_LIBRARY)
		#include "ezinject_injcode_uclibc.c"
	#endif
#elif defined(EZ_TARGET_WINDOWS)
	#include "ezinject_injcode_windows.c"
#else // FreeBSD || Android
INLINE void *inj_get_libdl(struct injcode_ctx *ctx){
	return ctx->br->libdl_handle;
}
#endif

#ifdef EZ_TARGET_POSIX
#undef EXIT_FAILURE
#undef EXIT_SUCCESS
#define EXIT_FAILURE SIGTRAP
#define EXIT_SUCCESS SIGSTOP
#endif

#if defined(EZ_TARGET_DARWIN)
#define PL_RETURN(sc, x) do { \
	((sc)->result = (x)); \
	sc->libc_syscall(__NR_kill, \
		sc->libc_syscall(__NR_getpid), \
		SIGSTOP \
	); \
	while(1); \
} while(0)
#elif defined(EZ_TARGET_POSIX)
#define PL_RETURN(sc, x) return (x)
#elif defined(EZ_TARGET_WINDOWS)
#define PL_RETURN(sc, x) do { \
	((sc)->result = (x)); \
	asm volatile("int $3\n"); \
	return 0; \
} while(0)
#else
#error "Unsupported platform"
#endif


INLINE intptr_t inj_libdl_init(struct injcode_ctx *ctx){
	struct injcode_bearing *br = ctx->br;
	struct dl_api *libdl = &ctx->libdl;

	void *libdl_handle = br->libdl_handle;
	// acquire libdl
	if(libdl_handle == NULL){
		inj_dchar(br, 'l');

		libdl_handle = inj_get_libdl(ctx);
		inj_dbgptr(br, libdl_handle);
		if(libdl_handle == NULL){
			inj_dchar(br, '!');
			return -1;
		}
	}
	libdl->dlopen = (void *)PTRADD(libdl_handle, br->dlopen_offset);
	libdl->dlclose = (void *)PTRADD(libdl_handle, br->dlclose_offset);
	libdl->dlsym = (void *)PTRADD(libdl_handle, br->dlsym_offset);
	return 0;
}

INLINE intptr_t inj_load_library(struct injcode_ctx *ctx){
	struct injcode_bearing *br = ctx->br;

	int (*crt_init)(struct injcode_bearing *br);
	char *sym_crt_init = NULL;
	STRTBL_FETCH(ctx->stbl, sym_crt_init);

	// fetch argv[0], the library absolute path
	char *stbl_argv = BR_STRTBL(br) + br->argv_offset;
	STRTBL_FETCH(stbl_argv, ctx->userlib_name);

	br->userlib = inj_dlopen(ctx, ctx->userlib_name, RTLD_NOW);

	//inj_dbgptr(br, br->userlib);
	if(br->userlib == NULL){
		return -1;
	}
	crt_init = ctx->libdl.dlsym(br->userlib, sym_crt_init);
	inj_dbgptr(br, crt_init);
	if(crt_init == NULL){
		return -2;
	}
	if(crt_init(br) != 0){
		return -3;
	}
	return 0;
}

intptr_t PLAPI injected_fn(struct injcode_call *sc){
	struct injcode_bearing *br = (struct injcode_bearing *)(sc->argv[0]);

	struct injcode_ctx stack_ctx;
	struct injcode_ctx *ctx = &stack_ctx;
	inj_memset(ctx, 0x00, sizeof(*ctx));
	ctx->br = br;
	ctx->stbl = BR_STRTBL(br);

	if(br->pl_debug){
		return 0;
	}

	// entry
	inj_dchar(br, 'e');

	STRTBL_FETCH(ctx->stbl, ctx->libdl_name);
	STRTBL_FETCH(ctx->stbl, ctx->libpthread_name);

	if(inj_libdl_init(ctx) != 0){
		inj_dchar(br, '!');
		PL_RETURN(sc, INJ_ERR_LIBDL);
	}

	// acquire libpthread
	inj_dchar(br, 'p');

	//had_pthread = dlopen(libpthread_name, RTLD_NOLOAD) != NULL;
	inj_puts(br, ctx->libpthread_name);
	ctx->h_libthread = inj_dlopen(ctx, ctx->libpthread_name, RTLD_LAZY | RTLD_GLOBAL);
	if(!ctx->h_libthread){
		inj_dchar(br, '!');
		inj_dchar(br, '1');
		char *errstr = NULL;
		if(ctx->libdl.dlerror && (errstr=ctx->libdl.dlerror()) != NULL){
			inj_puts(br, errstr);
		}
		PL_RETURN(sc, INJ_ERR_LIBPTHREAD);
	}
	inj_dbgptr(br, ctx->h_libthread);

	if(inj_api_init(ctx) != 0){
		inj_dchar(br, '!');
		inj_dchar(br, '2');
		PL_RETURN(sc, INJ_ERR_API);
	}

	// setup
	inj_dchar(br, 's');
	if(inj_load_prepare(ctx) != 0){
		inj_dchar(br, '!');
	}

	// dlopen
	inj_dchar(br, 'd');
	if(inj_load_library(ctx) != 0){
		inj_dchar(br, '!');
		PL_RETURN(sc, INJ_ERR_DLOPEN);
	}

	// wait for the thread to notify us
	inj_dchar(br, 'w');
	intptr_t result = 0;
	if(inj_thread_wait(ctx, &result) != 0){
		inj_dchar(br, '!');
		PL_RETURN(sc, INJ_ERR_WAIT);
	}

	if((enum userlib_return_action)result != userlib_persist){
		// cleanup
		inj_dchar(br, 'c');
		{
			/**
			 * NOTE: uclibc old might trigger segfaults in the user library while doing this (sigh)
			 **/
			ctx->libdl.dlclose(br->userlib);

			#ifndef UCLIBC_OLD
			/*if(!had_pthread){
				dlclose(h_pthread);
			}*/
			#endif
		}
	}


	// bye
	inj_dchar(br, 'b');
	PL_RETURN(sc, 0);
	return 0;
}
