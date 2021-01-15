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
#include <sys/prctl.h>

#include "config.h"

#include "ezinject_compat.c"

#include "ezinject_common.h"
#include "ezinject_arch.h"
#include "ezinject_injcode.h"

#ifndef HAVE_SHM_SYSCALLS
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

void trampoline(){
	EMIT_LABEL("trampoline_entry");

	register volatile struct injcode_bearing *br;
	register void (*target)(volatile struct injcode_bearing *);

	EMIT_POP(br);
	EMIT_POP(target);
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
#else
#define DBGPTR(ptr)
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

void injected_fn(struct injcode_bearing *br){
	void *h_pthread = NULL;
	int had_pthread = 0;

	void *(*dlopen)(const char *filename, int flag) = NULL;
	void *(*dlsym)(void *handle, const char *symbol) = NULL;
	int (*dlclose)(void *handle) = NULL;

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
				if(libdl_handle == NULL){
					PL_DBG('!');
					break;
				}
			}
		}
		dlopen = (void *)PTRADD(libdl_handle, br->dlopen_offset);
		dlclose = (void *)PTRADD(libdl_handle, br->dlclose_offset);
		dlsym = (void *)PTRADD(libdl_handle, br->dlsym_offset);
		DBGPTR(libdl_handle);

		char *libdl_name = NULL;
		char *libpthread_name = NULL;
		char *userlib_name = NULL;

		char *sym_pthread_mutex_init = NULL;
		char *sym_pthread_mutex_lock = NULL;
		char *sym_pthread_mutex_unlock = NULL;
		char *sym_pthread_cond_init = NULL;
		char *sym_pthread_cond_wait = NULL;
		char *sym_pthread_join = NULL;
		do {
			char *stbl = BR_STRTBL(br);
			STRTBL_FETCH(stbl, libdl_name);
			STRTBL_FETCH(stbl, libpthread_name);
			STRTBL_FETCH(stbl, sym_pthread_mutex_init);
			STRTBL_FETCH(stbl, sym_pthread_mutex_lock);
			STRTBL_FETCH(stbl, sym_pthread_mutex_unlock);
			STRTBL_FETCH(stbl, sym_pthread_cond_init);
			STRTBL_FETCH(stbl, sym_pthread_cond_wait);
			STRTBL_FETCH(stbl, sym_pthread_join);
			STRTBL_FETCH(stbl, userlib_name); // argv[0]
		} while(0);

		// just to make sure it's really loaded
		void *h_libdl = dlopen(libdl_name, RTLD_NOLOAD);
		DBGPTR(h_libdl);
		if(h_libdl == NULL){
			dlopen(libdl_name, RTLD_NOW | RTLD_GLOBAL);
		}

		// acquire libpthread
		PL_DBG('p');
		{
			had_pthread = dlopen(libpthread_name, RTLD_NOLOAD) != NULL;

			h_pthread = dlopen(libpthread_name, RTLD_LAZY | RTLD_GLOBAL);
			if(!h_pthread){
				PL_DBG('!');
				PL_DBG('1');
				break;
			}

			pthread_mutex_init = dlsym(h_pthread, sym_pthread_mutex_init);
			pthread_mutex_lock = dlsym(h_pthread, sym_pthread_mutex_lock);
			pthread_mutex_unlock = dlsym(h_pthread, sym_pthread_mutex_unlock);
			pthread_cond_init = dlsym(h_pthread, sym_pthread_cond_init);
			pthread_cond_wait = dlsym(h_pthread, sym_pthread_cond_wait);
			pthread_join = dlsym(h_pthread, sym_pthread_join);

			if(!pthread_mutex_init || !pthread_mutex_lock
			|| !pthread_mutex_unlock || !pthread_cond_init
			|| !pthread_cond_wait || !pthread_join
			){
				PL_DBG('!');
				PL_DBG('2');
				break;
			}
		}

		// initialize signal
		PL_DBG('s');
		pthread_mutex_init(&br->mutex, 0);
		pthread_cond_init(&br->cond, 0);

		// dlopen
		PL_DBG('d');
		{
			br->userlib = dlopen(userlib_name, RTLD_NOW);
			if(br->userlib == NULL){
				PL_DBG('!');
				break;
			}

			DBGPTR(br->userlib);
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
