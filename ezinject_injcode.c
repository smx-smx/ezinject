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
#include <sys/wait.h>
#include <sys/syscall.h>
#endif

#if defined(EZ_TARGET_LINUX)
#include <sys/prctl.h>
#endif

#include "ezinject_compat.h"

#ifdef EZ_TARGET_POSIX
#include "ezinject_compat.c"
#endif

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

#define BR_USERDATA(br) ((char *)br + SIZEOF_BR(*br))

void PLAPI injected_sc(){
	EMIT_LABEL("injected_sc_start");
	EMIT_SC();
	EMIT_LABEL("injected_sc_end");
}

//#define PL_EARLYDEBUG

void PLAPI trampoline(){
	EMIT_LABEL("trampoline_entry");
	
	#ifdef PL_EARLYDEBUG
	EMIT_LABEL("inj_halt");
	asm volatile(JMP_INSN" inj_halt");
	#endif

	register volatile struct injcode_bearing *br;
	register void (*target)(volatile struct injcode_bearing *);

	POP_PARAMS(br, target);
	target(br);
	while(1);
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

#ifdef DEBUG
#if defined(EZ_TARGET_POSIX)
#define DBGPTR(br, ptr) do { \
	const uint64_t buf[2] = { \
		str64(0x706C3A7074723A25), /* pl:ptr:% */ \
		str64(0x700A000000000000)  /* p\n\0    */ \
	}; \
	br->libc_printf((char *)buf, ptr); \
} while(0);
#elif defined(EZ_TARGET_WINDOWS)
#define DBGPTR(br, x) dbg_bin(br, (uintptr_t)x)

#else // DEBUG
#define DBGPTR(br, x)
INLINE void inj_puts(struct injcode_bearing *br, char *str){
	UNUSED(br);
	UNUSED(str);
}
#endif
#endif // DEBUG

struct dl_api {
#if defined(EZ_TARGET_POSIX)
	void *(*dlopen)(const char *filename, int flag);
#elif defined(EZ_TARGET_WINDOWS)
	void *(*dlopen)(const char *filename);
#endif
	void *(*dlsym)(void *handle, const char *symbol);
	int (*dlclose)(void *handle);
	char *(*dlerror)(void);
};

struct thread_api {
#if defined(EZ_TARGET_POSIX)
	int (*pthread_mutex_init)(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
	int (*pthread_mutex_lock)(pthread_mutex_t *mutex);
	int (*pthread_mutex_unlock)(pthread_mutex_t *mutex);
	int (*pthread_cond_init)(pthread_cond_t *cond, const pthread_condattr_t *attr);
	int (*pthread_cond_wait)(pthread_cond_t *restrict cond, pthread_mutex_t *restrict mutex);
	int (*pthread_join)(pthread_t thread, void **retval);
#elif defined(EZ_TARGET_WINDOWS)
	HANDLE (*CreateEventA)(
		LPSECURITY_ATTRIBUTES lpEventAttributes,
		BOOL                  bManualReset,
		BOOL                  bInitialState,
		LPCSTR                lpName
	);
	HANDLE (*CreateThread)(
		LPSECURITY_ATTRIBUTES   lpThreadAttributes,
		SIZE_T                  dwStackSize,
		LPTHREAD_START_ROUTINE  lpStartAddress,
		__drv_aliasesMem LPVOID lpParameter,
		DWORD                   dwCreationFlags,
		LPDWORD                 lpThreadId
	);
	BOOL (*CloseHandle)(
  		HANDLE hObject
	);
	DWORD (*WaitForSingleObject)(
		HANDLE hHandle,
		DWORD  dwMilliseconds
	);
	BOOL (*GetExitCodeThread)(
		HANDLE  hThread,
		LPDWORD lpExitCode
	);
#endif
};


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

#if defined(EZ_TARGET_POSIX)
#include "ezinject_injcode_posix_common.c"
#elif defined(EZ_TARGET_WINDOWS)
#include "ezinject_injcode_windows_common.c"
#endif


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

INLINE void *inj_dlopen(struct injcode_ctx *ctx, const char *filename, unsigned flags){
#if defined(EZ_TARGET_POSIX)
	return ctx->libdl.dlopen(filename, flags);
#elif defined(EZ_TARGET_WINDOWS)
	UNUSED(flags);
	return ctx->libdl.dlopen(filename);
#endif
}

INLINE void inj_thread_stop(struct injcode_ctx *ctx, int signal){
#if defined(EZ_TARGET_POSIX)
	// awake ptrace
	// success: SIGSTOP
	// failure: anything else
	struct injcode_bearing *br = ctx->br;
	br->libc_syscall(__NR_kill, br->libc_syscall(__NR_getpid), signal);
#elif defined(EZ_TARGET_WINDOWS)
	UNUSED(ctx);
	UNUSED(signal);
	asm volatile("int $3\n");
#endif
	while(1);
}

INLINE intptr_t inj_libdl_init(struct injcode_ctx *ctx){
	struct injcode_bearing *br = ctx->br;
	struct dl_api *libdl = &ctx->libdl;

	void *libdl_handle = br->libdl_handle;
	// acquire libdl
	if(libdl_handle == NULL){
		inj_dchar(br, 'l');

		libdl_handle = inj_get_libdl(ctx);
		DBGPTR(br, libdl_handle);
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

	//DBGPTR(br, br->userlib);
	if(br->userlib == NULL){
		return -1;
	}
	crt_init = ctx->libdl.dlsym(br->userlib, sym_crt_init);
	DBGPTR(br, crt_init);
	if(crt_init == NULL){
		return -2;
	}
	if(crt_init(br) != 0){
		return -3;
	}
	return 0;
}

void PLAPI injected_fn(struct injcode_bearing *br){
	struct injcode_ctx stack_ctx = {
		.br = br,
		.stbl = BR_STRTBL(br)
	};
	struct injcode_ctx *ctx = &stack_ctx;

	if(br->pl_debug){
		inj_thread_stop(ctx, EXIT_SUCCESS);
	}

	int signal = EXIT_FAILURE;

	do {
		// entry
		inj_dchar(br, 'e');

		STRTBL_FETCH(ctx->stbl, ctx->libdl_name);
		STRTBL_FETCH(ctx->stbl, ctx->libpthread_name);

		if(inj_libdl_init(ctx) != 0){
			inj_dchar(br, '!');
			break;
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
			break;
		}
		DBGPTR(br, ctx->h_libthread);

		if(inj_api_init(ctx) != 0){
			inj_dchar(br, '!');
			inj_dchar(br, '2');
			break;
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
			break;
		}

		// wait for the thread to notify us
		inj_dchar(br, 'w');
		intptr_t result = 0;
		if(inj_thread_wait(ctx, &result) != 0){
			inj_dchar(br, '!');
		}
		result = 1;

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

		signal = EXIT_SUCCESS;
	} while(0);


	// bye
	inj_dchar(br, 'b');

	inj_thread_stop(ctx, signal);
}
