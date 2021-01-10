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

INLINE int br_semop(struct injcode_bearing *br, int sema, int idx, int op){
	struct sembuf sem_op = {
		.sem_num = idx,
		.sem_op = op,
		.sem_flg = 0
	};
	// prefer libc semop, if available
	if(br->libc_semop != NULL){
		return br->libc_semop(sema, &sem_op, 1);
	}

	// use built-in compatibility semop
	return semop(br, sema, &sem_op, 1);
}

#if defined(HAVE_LIBC_DLOPEN_MODE)
#include "ezinject_injcode_glibc.c"
#elif defined(HAVE_DL_LOAD_SHARED_LIBRARY)
#include "ezinject_injcode_uclibc.c"
#else
INLINE void *get_libdl(struct injcode_bearing *br){
	return br->libdl_handle;
}
#endif

INLINE int inj_get_sema(struct injcode_bearing *br){
	pid_t pid = br->libc_syscall(__NR_getpid);
	int sema = semget(br, pid, 1, 0);
	if(sema < 0){
		return sema;
	}

	// initialize signal
	int rc = br_semop(br, sema, EZ_SEM_LIBCTL, 1);
	if(rc < 0){
		return rc;
	}
	return sema;
}

void injected_fn(struct injcode_bearing *br){
	int sema = -1;

	void *h_pthread = NULL;
	int had_pthread = 0;

	void *(*dlopen)(const char *filename, int flag) = NULL;
	void *(*dlsym)(void *handle, const char *symbol) = NULL;
	int (*dlclose)(void *handle) = NULL;
	int (*pthread_join)(pthread_t thread, void **retval) = NULL;

	int signal = SIGTRAP;

	do {

		if(br->pl_debug){
			inj_halt: goto inj_halt;
		}

		// entry
		PL_DBG('e');

		// acquire semaphores
		PL_DBG('s');
		if((sema = inj_get_sema(br)) < 0){
			PL_DBG('!');
			break;
		}

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
		char *sym_pthread_join = NULL;
		char *userlib_name = NULL;

		do {
			char *stbl = BR_STRTBL(br);
			STRTBL_FETCH(stbl, libdl_name);
			STRTBL_FETCH(stbl, libpthread_name);
			STRTBL_FETCH(stbl, sym_pthread_join);
			STRTBL_FETCH(stbl, userlib_name);
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

			pthread_join = dlsym(h_pthread, sym_pthread_join);
			if(!pthread_join){
				PL_DBG('!');
				PL_DBG('2');
				break;
			}
		}

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
		br_semop(br, sema, EZ_SEM_LIBCTL, 0);

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
