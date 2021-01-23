#define _GNU_SOURCE
#define EZINJECT_INJCODE

#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sched.h>
#include <pthread.h>
#include <link.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#include "config.h"

#if defined(EZ_TARGET_LINUX)
#include <sys/prctl.h>
#endif

#include "ezinject_compat.c"

#include "ezinject_common.h"
#include "ezinject_arch.h"
#include "ezinject_injcode.h"

#if defined(EZ_TARGTE_LINUX) && !defined(HAVE_SHM_SYSCALLS)
#include <asm-generic/ipc.h>
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
	#if BYTE_ORDER == BIG_ENDIAN
		return x;
	#elif BYTE_ORDER == LITTLE_ENDIAN
		return __builtin_bswap64(x);
	#else
		#error "Unknown endianness"
	#endif
}

#ifdef DEBUG
#define DBGPTR(ptr) do { \
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
#define DBGPTR(ptr)
INLINE void br_puts(struct injcode_bearing *br, char *str){}
#endif

#if defined(HAVE_LIBC_DLOPEN_MODE)
#include "ezinject_injcode_glibc.c"
#elif defined(HAVE_DL_LOAD_SHARED_LIBRARY)
#include "ezinject_injcode_uclibc.c"
#else
INLINE void *get_libdl(struct injcode_bearing *br){
	return br->libdl_handle;
}
#endif

#ifdef EZ_ARCH_ARM
INLINE void br_cacheflush(struct injcode_bearing *br, void *from, void *to){
	br->libc_syscall(__ARM_NR_cacheflush, from, to, 0);
}
#else
INLINE void br_cacheflush(struct injcode_bearing *br, void *from, void *to){}
#endif

void injected_fn(struct injcode_bearing *br){
	void *h_pthread = NULL;
	int had_pthread = 0;

	void *(*dlopen)(const char *filename, int flag) = NULL;
	void *(*dlsym)(void *handle, const char *symbol) = NULL;
	int (*dlclose)(void *handle) = NULL;
	char *(*dlerror)(void) = NULL;

	int (*pthread_mutex_init)(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) = NULL;
	int (*pthread_mutex_lock)(pthread_mutex_t *mutex) = NULL;
	int (*pthread_mutex_unlock)(pthread_mutex_t *mutex) = NULL;
	int (*pthread_cond_init)(pthread_cond_t *cond, const pthread_condattr_t *attr) = NULL;
	int (*pthread_cond_wait)(pthread_cond_t *restrict cond, pthread_mutex_t *restrict mutex) = NULL;
	int (*pthread_join)(pthread_t thread, void **retval) = NULL;

	int signal = SIGTRAP;

	do {

		if(br->pl_debug){
			inj_halt: goto inj_halt;
		}

		// entry
		PL_DBG('e');

		void *libdl_handle = br->libdl_handle;
		// acquire libdl
		if(libdl_handle == NULL){
			PL_DBG('l');
			{
				libdl_handle = get_libdl(br);
				DBGPTR(libdl_handle);
				if(libdl_handle == NULL){
					PL_DBG('!');
					break;
				}
			}
		}
		dlopen = (void *)PTRADD(libdl_handle, br->dlopen_offset);
		dlclose = (void *)PTRADD(libdl_handle, br->dlclose_offset);
		dlsym = (void *)PTRADD(libdl_handle, br->dlsym_offset);

		PL_DBG('x');
		DBGPTR(libdl_handle);
		DBGPTR(dlopen);

		char *libdl_name = NULL;
		char *libpthread_name = NULL;
		char *userlib_name = NULL;

		//br->libc_syscall(__ARM_NR_cacheflush, sym_name, (void *)(UPTR(sym_name) + 256)); 

		#define FETCH_SYM(stbl, h_lib, sym) do { \
			char *sym_name; \
			STRTBL_FETCH(stbl, sym_name); \
			br_cacheflush(br, &sym_name, (void *)(UPTR(&sym_name) + sizeof(sym_name))); \
			sym = dlsym(h_lib, sym_name); \
		} while(0)

		char *stbl = BR_STRTBL(br);
		STRTBL_FETCH(stbl, libdl_name);
		STRTBL_FETCH(stbl, libpthread_name);

		br_puts(br, libdl_name);
		// just to make sure it's really loaded
		void *h_libdl = dlopen(libdl_name, RTLD_NOLOAD);
		DBGPTR(h_libdl);
		if(h_libdl == NULL){
			h_libdl = dlopen(libdl_name, RTLD_NOW | RTLD_GLOBAL);
		}
		FETCH_SYM(stbl, h_libdl, dlerror);

		// acquire libpthread
		PL_DBG('p');
		{
			//had_pthread = dlopen(libpthread_name, RTLD_NOLOAD) != NULL;

			br_puts(br, libpthread_name);
			h_pthread = dlopen(libpthread_name, RTLD_LAZY | RTLD_GLOBAL);
			if(!h_pthread){
				PL_DBG('!');
				PL_DBG('1');
				if(dlerror){
					char *errstr = dlerror();
					if(errstr != NULL){
						br_puts(br, errstr);
					}
				}
				break;
			}
		}

		DBGPTR(h_pthread);
		FETCH_SYM(stbl, h_pthread, pthread_mutex_init);
		FETCH_SYM(stbl, h_pthread, pthread_mutex_lock);
		FETCH_SYM(stbl, h_pthread, pthread_mutex_unlock);
		FETCH_SYM(stbl, h_pthread, pthread_cond_init);
		FETCH_SYM(stbl, h_pthread, pthread_cond_wait);
		FETCH_SYM(stbl, h_pthread, pthread_join);

		if(!pthread_mutex_init || !pthread_mutex_lock
		|| !pthread_mutex_unlock || !pthread_cond_init
		|| !pthread_cond_wait || !pthread_join
		){
			PL_DBG('!');
			PL_DBG('2');
			break;
		}

		int (*crt_init)(struct injcode_bearing *br);
		char *sym_crt_init = NULL;
		STRTBL_FETCH(stbl, sym_crt_init);

		stbl = BR_STRTBL(br) + br->argv_offset;
		STRTBL_FETCH(stbl, userlib_name);

		// initialize signal
		PL_DBG('s');
		pthread_mutex_init(&br->mutex, 0);
		pthread_cond_init(&br->cond, 0);

		// dlopen
		PL_DBG('d');
		{
			br_puts(br, userlib_name);
			br->userlib = dlopen(userlib_name, RTLD_NOW);
			DBGPTR(br->userlib);
			if(br->userlib == NULL){
				PL_DBG('!');
				break;
			}
			crt_init = dlsym(br->userlib, sym_crt_init);
			DBGPTR(crt_init);
			if(crt_init == NULL){
				PL_DBG('!');
				break;
			}
			if(crt_init(br) != 0){
				PL_DBG('!');
				break;
			}
		}

		// wait for the thread to notify us
		PL_DBG('w');
		pthread_mutex_lock(&br->mutex);
		while(!br->loaded_signal){
			pthread_cond_wait(&br->cond, &br->mutex);
		}
		pthread_mutex_unlock(&br->mutex);

		void *result;

		// wait for user thread to die
		PL_DBG('j');
		pthread_join(br->user_tid, &result);

		if((enum userlib_return_action)result != userlib_persist){
			// cleanup
			PL_DBG('c');
			{
				/**
				 * NOTE: uclibc old might trigger segfaults in the user library while doing this (sigh)
				 **/
				dlclose(br->userlib);

				#ifndef UCLIBC_OLD
				if(!had_pthread){
					dlclose(h_pthread);
				}
				#endif
			}
		}

		signal = SIGSTOP;
	} while(0);


	// bye
	PL_DBG('b');

	// awake ptrace
	// success: SIGSTOP
	// failure: anything else
	br->libc_syscall(__NR_kill, br->libc_syscall(__NR_getpid), signal);
	while(1);
}

void injected_code_end(void){}
