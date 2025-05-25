/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#define EZINJECT_INJCODE

#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sched.h>
#include <pthread.h>
#include <sys/stat.h>

#ifdef EZ_TARGET_LINUX
#include <sys/syscall.h>
#endif

#include "config.h"

#ifdef EZ_TARGET_POSIX
#include <signal.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#endif

#if defined(EZ_TARGET_LINUX)
#include <sys/prctl.h>
#endif

#include "dlfcn_compat.h"
#include "ezinject_common.h"
#include "ezinject_compat.h"
#include "ezinject_arch.h"
#include "ezinject_injcode.h"

#ifdef EZ_TARGET_WINDOWS
// for BYTE_ORDER
#include <sys/param.h>
#endif

#define UNUSED(x) (void)(x)

#if defined(HAVE_LIBC_DLOPEN_MODE) || defined(HAVE_LIBC_DL_OPEN)
#define __RTLD_DLOPEN 0x80000000 /* glibc internal */
#endif

void SCAPI injected_sc_trap(void){
	EMIT_LABEL("injected_sc_trap_start");
	asm volatile("nop\n");
	asm volatile("nop\n");
	asm volatile("nop\n");
	asm volatile("nop\n");
	EMIT_LABEL("injected_sc_trap_stop");
	asm volatile(JMP_INSN " .");
}

#ifdef EZ_TARGET_LINUX
/**
 * Old glibc has broken syscall(3) argument handling for mmap
 * We must use the libc's mmap(3) instead, which handles them properly
 **/
intptr_t SCAPI injected_mmap(volatile struct injcode_call *sc){
	return (intptr_t)sc->libc_mmap(
		(void *)sc->argv[1], (size_t)sc->argv[2],
		(int)sc->argv[3], (int)sc->argv[4],
		(int)sc->argv[5], (off_t)sc->argv[6]
	);
}

intptr_t SCAPI injected_open(volatile struct injcode_call *sc){
	return (intptr_t)sc->libc_open((const char *)sc->argv[1], (int)sc->argv[2]);
}

intptr_t SCAPI injected_read(volatile struct injcode_call *sc){
	return (intptr_t)sc->libc_read((int)sc->argv[1], (void *)sc->argv[2], (size_t)sc->argv[3]);
}
#endif

#if defined(EZ_TARGET_LINUX) || defined(EZ_TARGET_FREEBSD)
INLINE void SCAPI injected_sc_stop(volatile struct injcode_call *sc){
	sc->libc_syscall(__NR_kill,
		sc->libc_syscall(__NR_getpid),
		SIGTRAP
	);
}
#elif defined(EZ_TARGET_WINDOWS)
INLINE void SCAPI injected_sc_stop(volatile struct injcode_call *sc){
	sc->ezstate = EZST1;
	asm volatile(JMP_INSN " .");
}
#endif

#if defined(EZ_TARGET_LINUX) || defined(EZ_TARGET_FREEBSD) || defined(EZ_TARGET_WINDOWS)
/**
 * On ARM/Linux + glibc, making system calls and writing their results in the same function
 * seems to cause a very subtle stack corruption bug that ultimately causes dlopen/dlsym to segfault
 * to work around that, we use a wrapper so that the system call is executed in a different subroutine
 * than the one setting the result.
 **/
void SCAPI injected_sc_wrapper(volatile struct injcode_call *args){
	args->result = args->wrapper.target(args);
	injected_sc_stop(args);
	asm volatile(JMP_INSN " .");
}
#endif

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

INLINE uint64_t inj_bswap64(uint64_t x){
	return  ( (x << 56) & 0xff00000000000000UL ) |
		( (x << 40) & 0x00ff000000000000UL ) |
		( (x << 24) & 0x0000ff0000000000UL ) |
		( (x <<  8) & 0x000000ff00000000UL ) |
		( (x >>  8) & 0x00000000ff000000UL ) |
		( (x >> 24) & 0x0000000000ff0000UL ) |
		( (x >> 40) & 0x000000000000ff00UL ) |
		( (x >> 56) & 0x00000000000000ffUL );
}

INLINE uint64_t str64(uint64_t x){
	#ifndef BYTE_ORDER
		#error "BYTE_ORDER not defined"
	#endif
	#if BYTE_ORDER == BIG_ENDIAN
		return x;
	#elif BYTE_ORDER == LITTLE_ENDIAN
		return inj_bswap64(x);
	#else
		#error "Unknown endianness"
	#endif
}

#define PCALL(ctx, fn, ...) ctx->plapi.fn(ctx, __VA_ARGS__)
#include "ezinject_injcode_common.c"

#if defined(EZ_TARGET_POSIX)
#include "ezinject_injcode_posix.h"
#elif defined(EZ_TARGET_WINDOWS)
#include "ezinject_injcode_windows.h"
#endif

#ifdef EZ_TARGET_WINDOWS
typedef HANDLE log_handle_t;
#else
typedef int log_handle_t;
#endif

struct injcode_ctx {
	struct injcode_bearing *br;

	log_handle_t log_handle;

	struct dl_api libdl;
	struct thread_api libthread;
	struct injcode_plapi plapi;
	struct ezinj_str *stbl;

	char *libdl_name;
	char *libpthread_name;
	char *userlib_name;

	/** handle to the library providing dynamic linkage **/
	void *h_libdl;
	/** handle to the library providing threads **/
	void *h_libthread;
};

#if defined(EZ_TARGET_POSIX)
#include "ezinject_injcode_posix_common.c"
#elif defined(EZ_TARGET_WINDOWS)
#include "ezinject_injcode_windows_common.c"
#endif

#include "ezinject_injcode_util.c"

intptr_t PLAPI inj_fetchsym(
	struct injcode_ctx *ctx,
	enum ezinj_str_id str_id,
	void *handle, void **sym
){
	char *sym_name = ctx->stbl[str_id].str;
#ifdef DEBUG
	PCALL(ctx, inj_puts, sym_name);
#endif
	inj_cacheflush(ctx->br, &sym_name, (void *)(UPTR(&sym_name) + sizeof(sym_name)));
	*sym = ctx->libdl.dlsym(handle, sym_name);
	if(*sym == NULL){
		PCALL(ctx, inj_dchar, '!');
		PCALL(ctx, inj_dchar, 's');
		PCALL(ctx, inj_puts, sym_name);
		return -1;
	}
	return 0;
}

#ifdef EZ_TARGET_POSIX
#include "ezinject_injcode_posix.c"
#endif

#ifdef EZ_TARGET_DARWIN
#include "ezinject_injcode_darwin.c"
#endif

#if defined(EZ_TARGET_LINUX) && !defined(EZ_TARGET_ANDROID) && !defined(HAVE_LIBDL_IN_LIBC)
	#if defined(HAVE_LIBC_DLOPEN_MODE) || defined(HAVE_LIBC_DL_OPEN)
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

INLINE intptr_t inj_libdl_init(struct injcode_ctx *ctx){
	struct injcode_bearing *br = ctx->br;
	struct dl_api *libdl = &ctx->libdl;

	void *libdl_handle = br->libdl_handle;
	// acquire libdl
	if(libdl_handle == NULL){
		PCALL(ctx, inj_dchar, 'l');

		libdl_handle = inj_get_libdl(ctx);
		PCALL(ctx, inj_dbgptr, libdl_handle);
		if(libdl_handle == NULL){
			PCALL(ctx, inj_dchar, '!');
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
	char *sym_crt_init = BR_STRTBL(br)[EZSTR_API_CRT_INIT].str;

	// fetch argv[0], the library absolute path
	ctx->userlib_name = BR_STRTBL(br)[EZSTR_ARGV0].str;

	PCALL(ctx, inj_puts, ctx->userlib_name);
	br->userlib = inj_dlopen(ctx, ctx->userlib_name, RTLD_NOW);

	PCALL(ctx, inj_dbgptr, br->userlib);
	if(br->userlib == NULL){
		return -1;
	}
	crt_init = ctx->libdl.dlsym(br->userlib, sym_crt_init);
	PCALL(ctx, inj_dbgptr, crt_init);
	if(crt_init == NULL){
		return -2;
	}
	if(crt_init(br) != 0){
		return -3;
	}
	return 0;
}

INLINE void inj_plapi_init(struct injcode_call *sc, struct injcode_ctx *ctx){
	#define PCOPY(x) ctx->plapi.x = sc->plapi.x
	PCOPY(inj_memset);
	PCOPY(inj_puts);
	PCOPY(inj_dchar);
	PCOPY(inj_dbgptr);
	PCOPY(inj_fetchsym);
	#undef PCOPY
}

intptr_t PLAPI injected_fn(struct injcode_call *sc){
	struct injcode_bearing *br = (struct injcode_bearing *)(sc->argv[0]);
	struct injcode_ctx stack_ctx;
	struct injcode_ctx *ctx = &stack_ctx;

	sc->plapi.inj_memset(NULL, ctx, 0x00, sizeof(*ctx));
	inj_plapi_init(sc, ctx);

	ctx->br = br;
	ctx->stbl = BR_STRTBL(br);

	// relocate the string table, if not done already
	if(!br->stbl_relocated){
		br->stbl_relocated = 1;

		/** convert string offsets to pointers */
		char *str_base = (char *)PTRADD(ctx->stbl, sizeof(struct ezinj_str) * br->num_strings);
		for(unsigned i=0; i<br->num_strings; i++){
			ctx->stbl[i].str = (char *)PTRADD(ctx->stbl[i].str, str_base);
		}
	}

	#if 0
	if(br->pl_debug){
		asm volatile(JMP_INSN " .");
	}
	#endif


	intptr_t result = 0;
	// entry
	inj_loginit(ctx);
	PCALL(ctx, inj_dchar, 'e');

	#ifdef EZ_TARGET_DARWIN
	int thread_is_parent = br->tid == 0;
	if(thread_is_parent){
		PCALL(ctx, inj_dchar, 't');

		sc->mach_thread = br->mach_thread_self();

		// sc->trampoline.fn_addr
		if(br->pthread_create_from_mach_thread(&br->tid, NULL, (void * (*)(void *))injected_fn, sc) != 0){
			PCALL(ctx, inj_dchar, '!');
			result = INJ_ERR_DARWIN_THREAD;
			goto pl_exit;
		}
		goto pl_exit;
	} else {
		// detach ourselves to free resources
		// (the parent can't do it because it has no TLS)
		br->pthread_detach(br->pthread_self());

		// kill the parent thread
		// (the parent can't do it because it has no TLS within `thread_terminate`)
		br->thread_terminate(sc->mach_thread);
	}
	#endif

	ctx->libdl_name = BR_STRTBL(br)[EZSTR_API_LIBDL].str;
	ctx->libpthread_name = BR_STRTBL(br)[EZSTR_API_LIBPTHREAD].str;

	if(inj_libdl_init(ctx) != 0){
		PCALL(ctx, inj_dchar, '!');
		result = INJ_ERR_LIBDL;
		goto pl_exit;
	}

	// acquire libpthread
	PCALL(ctx, inj_dchar, 'p');

	PCALL(ctx, inj_puts, ctx->libpthread_name);
	ctx->h_libthread = inj_dlopen(ctx, ctx->libpthread_name, RTLD_LAZY | RTLD_GLOBAL);
	if(!ctx->h_libthread){
		PCALL(ctx, inj_dchar, '!');
		PCALL(ctx, inj_dchar, '1');
		char *errstr = NULL;
		if(ctx->libdl.dlerror && (errstr=ctx->libdl.dlerror()) != NULL){
			PCALL(ctx, inj_puts, errstr);
		}
		result = INJ_ERR_LIBPTHREAD;
		goto pl_exit;
	}
	PCALL(ctx, inj_dbgptr, ctx->h_libthread);

	if(inj_api_init(ctx) != 0){
		PCALL(ctx, inj_dchar, '!');
		PCALL(ctx, inj_dchar, '2');
		ctx->libdl.dlclose(ctx->h_libthread);
		result = INJ_ERR_API;
		goto pl_exit;
	}

	// setup
	PCALL(ctx, inj_dchar, 's');
	if(inj_load_prepare(ctx) != 0){
		PCALL(ctx, inj_dchar, '!');
	}

	// dlopen
	PCALL(ctx, inj_dchar, 'd');
	if(inj_load_library(ctx) != 0){
		PCALL(ctx, inj_dchar, '!');
		ctx->libdl.dlclose(ctx->h_libthread);
		char *errstr = NULL;
		if(ctx->libdl.dlerror && (errstr=ctx->libdl.dlerror()) != NULL){
			PCALL(ctx, inj_puts, errstr);
		} else {
			PCALL(ctx, inj_dchar, '?');
		}
		result = INJ_ERR_DLOPEN;
		goto pl_exit;
	}

	// wait for the thread to notify us
	PCALL(ctx, inj_dchar, 'w');

	// exit status from lib_main
	if(inj_thread_wait(ctx, &result) != 0){
		PCALL(ctx, inj_dchar, '!');
		ctx->libdl.dlclose(ctx->h_libthread);
		result = INJ_ERR_WAIT;
		goto pl_exit;
	}

	if(br->user.persist == 0){
		// cleanup
		PCALL(ctx, inj_dchar, 'c');
		/**
		 * NOTE: some C libraries might cause a segfault during this call
		 * the segfault will be trapped by ezinject, so (hopefully) the process can continue
		 **/
		ctx->libdl.dlclose(br->userlib);
	}

	result = 0;


pl_exit:
	// bye
	PCALL(ctx, inj_dchar, 'b');

	// XXX: if we close pthread and it wasn't open before, bad things can happen
	/*if(ctx->h_libthread != NULL){
		ctx->libdl.dlclose(ctx->h_libthread);
	}*/

	inj_logfini(ctx);

	#ifdef EZ_TARGET_DARWIN
	if(thread_is_parent){
		// it looks we can't kill a thread created from `thread_create_running`, so we do hacks
		asm volatile(JMP_INSN " .");
		//return 0;
	} else {
		sc->result = result;
		br->libc_syscall(__NR_kill,
			br->libc_syscall(__NR_getpid),
			SIGSTOP);
		return 0;
	}
	#else
	// return to ezinject
	PL_RETURN(sc, result);
	#endif

	asm volatile(JMP_INSN " .");

	// should never be reached
	return 0;
}
