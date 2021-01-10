#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sched.h>
#include <pthread.h>
#include <link.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

#include "config.h"
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

//pl:x\n\0
#ifdef DEBUG
#define DBG(ch) do { \
	const uint64_t str = str64(0x706C3A000A000000 | (((uint64_t)ch << 32) & 0xFF00000000)); \
	br->libc_syscall(__NR_write, STDOUT_FILENO, &str, 5); \
} while(0)

#else
#define DBG(ch)
#endif

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

INLINE int br_semget(struct injcode_bearing *br, key_t key, int nsems, int semflg){
#ifdef HAVE_SHM_SYSCALLS
	return br->libc_syscall(__NR_semget, key, nsems, semflg);
#else
	return br->libc_syscall(__NR_ipc, IPCCALL(0, SEMGET), key, nsems, semflg);
#endif
}

INLINE int br_semop(struct injcode_bearing *br, int sema, int idx, int op){
	struct sembuf sem_op = {
		.sem_num = idx,
		.sem_op = op,
		.sem_flg = 0
	};
	return br->libc_semop( sema, &sem_op, 1);
}

#if defined(HAVE_LIBC_DLOPEN_MODE)
#include "ezinject_injcode_glibc.c"
#elif defined(HAVE_DL_LOAD_SHARED_LIBRARY)
#include "ezinject_injcode_uclibc.c"
#endif

INLINE int inj_get_sema(struct injcode_bearing *br){
	pid_t pid = br->libc_syscall(__NR_getpid);
	int sema = br_semget(br, pid, 1, 0);
	if(sema < 0){
		return sema;
	}

	// initialize signal
	br_semop(br, sema, EZ_SEM_LIBCTL, 1);
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
		DBG('e');

		// acquire semaphores
		DBG('s');
		if((sema = inj_get_sema(br)) < 0){
			DBG('!');
			break;
		}

		void *libdl_handle = br->libdl_handle;
		// acquire libdl
		if(libdl_handle == NULL){
			DBG('l');
			{
				libdl_handle = get_libdl(br);
				if(libdl_handle == NULL){
					DBG('!');
					break;
				}
			}
		}
		dlopen = (void *)PTRADD(libdl_handle, br->dlopen_offset);
		dlclose = (void *)PTRADD(libdl_handle, br->dlclose_offset);
		dlsym = (void *)PTRADD(libdl_handle, br->dlsym_offset);

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
		if(h_libdl == NULL){
			dlopen(libdl_name, RTLD_NOW | RTLD_GLOBAL);
		}

		// acquire libpthread
		DBG('p');
		{
			had_pthread = dlopen(libpthread_name, RTLD_NOLOAD) != NULL;

			h_pthread = dlopen(libpthread_name, RTLD_LAZY | RTLD_GLOBAL);
			if(!h_pthread){
				DBG('!');
				break;
			}

			pthread_join = dlsym(h_pthread, sym_pthread_join);
			if(!pthread_join){
				DBG('!');
				break;
			}
		}

		// dlopen
		DBG('d');
		{
			br->userlib = dlopen(userlib_name, RTLD_NOW);
			if(br->userlib == NULL){
				DBG('!');
				break;
			}

			#ifdef DEBUG
			const uint64_t buf[2] = {
				str64(0x706C3A757365726C), //pl:userl
				str64(0x69623A25700A0000)  //ib:%p\n\0
			};
			br->libc_printf((char *)buf, br->userlib);
			#endif
		}

		// wait for the thread to notify us
		DBG('w');
		br_semop(br, sema, EZ_SEM_LIBCTL, 0);

		void *result;

		// wait for user thread to die
		DBG('j');
		pthread_join(br->user_tid, &result);

		if((enum userlib_return_action)result != userlib_persist){
			// cleanup
			DBG('c');
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
	DBG('b');

	// awake ptrace
	// success: SIGSTOP
	// failure: anything else
	br->libc_syscall(__NR_kill, br->libc_syscall(__NR_getpid), signal);
	while(1);
}

void injected_code_end(void){}
