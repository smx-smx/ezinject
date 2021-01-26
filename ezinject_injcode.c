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

void injected_code_start(void){}

void injected_sc(){
	EMIT_LABEL("injected_sc_start");
	EMIT_SC();
	EMIT_LABEL("injected_sc_end");
}

//#define PL_EARLYDEBUG

void trampoline(){
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

#if defined(DEBUG) && defined(EZ_TARGET_POSIX)
#define DBGPTR(br, ptr) do { \
	const uint64_t buf[2] = { \
		str64(0x706C3A7074723A25), /* pl:ptr:% */ \
		str64(0x700A000000000000)  /* p\n\0    */ \
	}; \
	br->libc_printf((char *)buf, ptr); \
} while(0);
INLINE void br_puts(struct injcode_bearing *br, char *str){
	if(str == NULL){
		return;
	}

	int l;
	for(l=0; str[l] != 0x00; l++);
	br->libc_syscall(__NR_write, STDOUT_FILENO, str, l);
	char nl = '\n';
	
	br->libc_syscall(__NR_write, STDOUT_FILENO, &nl, 1);
}
#else
#define DBGPTR(br, ptr)
INLINE void br_puts(struct injcode_bearing *br, char *str){
	if(str == NULL){
		return;
	}

	PPEB peb = br->RtlGetCurrentPeb();
	PINT_RTL_USER_PROCESS_PARAMETERS params = (PINT_RTL_USER_PROCESS_PARAMETERS)peb->ProcessParameters;
	
	HANDLE h = params->StandardOutput;
	if(h == INVALID_HANDLE_VALUE){
		return;
	}

	int l = 0;
	char *p = str;
	while(*(p++)) ++l;

	IO_STATUS_BLOCK stb;
	br->NtWriteFile(h, NULL, NULL, NULL, &stb, str, l, 0, NULL);

	char nl[2];
	nl[0] = '\r'; nl[1] = '\n';
	br->NtWriteFile(h, NULL, NULL, NULL, &stb, nl, sizeof(nl), 0, NULL);
}
#endif


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

#ifdef EZ_ARCH_ARM
INLINE void br_cacheflush(struct injcode_bearing *br, void *from, void *to){
	br->libc_syscall(__ARM_NR_cacheflush, from, to, 0);
}
#else
INLINE void br_cacheflush(struct injcode_bearing *br, void *from, void *to){
	UNUSED(br);
	UNUSED(from);
	UNUSED(to);
}
#endif

INLINE intptr_t fetch_sym(
	struct injcode_ctx *ctx,
	void *handle, void **sym
){
	char *sym_name;
	// advances stbl in ctx
	STRTBL_FETCH(ctx->stbl, sym_name);
#ifdef DEBUG
	br_puts(ctx->br, sym_name);
#endif
	br_cacheflush(ctx->br, &sym_name, (void *)(UPTR(&sym_name) + sizeof(sym_name)));
	*sym = ctx->libdl.dlsym(handle, sym_name);
	if(*sym == NULL){
		PL_DBG(ctx->br, '!');
		PL_DBG(ctx->br, 's');
		br_puts(ctx->br, sym_name);
		return -1;
	}
	return 0;
}

#include "ezinject_injcode_util.c"

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

INLINE int inj_api_check(struct injcode_ctx *ctx){
	struct thread_api *api = &ctx->libthread;
	int nPointers = sizeof(*api) / sizeof(uintptr_t);
	uintptr_t *ptrs = (uintptr_t *)api;
	for(int i=0; i<nPointers; i++){
		if(ptrs[i] == 0){
			return -1;
		}
	}
	return 0;
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
		PL_DBG(br, 'l');

		libdl_handle = inj_get_libdl(ctx);
		DBGPTR(br, libdl_handle);
		if(libdl_handle == NULL){
			PL_DBG(br, '!');
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

void injected_fn(struct injcode_bearing *br){
	struct injcode_ctx stack_ctx = {
		.br = br,
		.stbl = BR_STRTBL(br)
	};
	struct injcode_ctx *ctx = &stack_ctx;

	if(br->pl_debug){
		inj_thread_stop(ctx, EXIT_FAILURE);
	}

	int signal = EXIT_FAILURE;

	do {
		// entry
		PL_DBG(br, 'e');

		STRTBL_FETCH(ctx->stbl, ctx->libdl_name);
		STRTBL_FETCH(ctx->stbl, ctx->libpthread_name);

		if(inj_libdl_init(ctx) != 0){
			PL_DBG(br, '!');
			break;
		}

		// acquire libpthread
		PL_DBG(br, 'p');

		//had_pthread = dlopen(libpthread_name, RTLD_NOLOAD) != NULL;
		br_puts(br, ctx->libpthread_name);
		ctx->h_libthread = inj_dlopen(ctx, ctx->libpthread_name, RTLD_LAZY | RTLD_GLOBAL);
		if(!ctx->h_libthread){
			PL_DBG(br, '!');
			PL_DBG(br, '1');
			char *errstr = NULL;
			if(ctx->libdl.dlerror && (errstr=ctx->libdl.dlerror()) != NULL){
				br_puts(br, errstr);
			}
			break;
		}
		DBGPTR(br, ctx->h_libthread);

		if(inj_api_init(ctx) != 0
		|| inj_api_check(ctx) != 0){
			PL_DBG(br, '!');
			PL_DBG(br, '2');
			break;
		}

	#ifdef EZ_TARGET_WINDOWS
	PL_DBG(br, 's');
	br->hEvent = ctx->libthread.CreateEventA(
		NULL,
		TRUE,
		FALSE,
		NULL
	);
	if(br->hEvent == INVALID_HANDLE_VALUE){
		PL_DBG(br, '!');
	}
	#endif

		// dlopen
		PL_DBG(br, 'd');
		if(inj_load_library(ctx) != 0){
			PL_DBG(br, '!');
			break;
		}

		// wait for the thread to notify us
		PL_DBG(br, 'w');
		intptr_t result = 0;
		if(inj_thread_wait(ctx, &result) != 0){
			PL_DBG(br, '!');
		}
		result = 1;

		if((enum userlib_return_action)result != userlib_persist){
			// cleanup
			PL_DBG(br, 'c');
			{
				/**
				 * NOTE: uclibc old might trigger segfaults in the user library while doing this (sigh)
				 **/
				dlclose(br->userlib);

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
	PL_DBG(br, 'b');

	inj_thread_stop(ctx, signal);
}

void injected_code_end(void){}
