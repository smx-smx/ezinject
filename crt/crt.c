#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <sched.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <asm/unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

#include <pthread.h>

#include <dlfcn.h>

#include "ezinject.h"
#include "ezinject_injcode.h"

#include "log.h"

#ifdef DEBUG
#include "util.h"
#endif

#ifndef MODULE_NAME
#define MODULE_NAME "userlib"
#endif

#define UNUSED(x) (void)(x)

extern int crt_userinit(struct injcode_bearing *br);

struct crt_params {
	pid_t pid;
	void *mem;
	int sema;
};

static struct crt_params gParams;

void* real_entry(void *arg);

INLINE void *acquire_shm(key_t key){
	int shm_id = shmget(key, MAPPINGSIZE, 0);
	if(shm_id < 0){
		perror("shmget");
		return NULL;
	}
	void *mem = shmat(shm_id, NULL, 0);
	if(mem == MAP_FAILED){
		perror("shmat");
		return NULL;
	}

	return mem;
}

extern void ret_start(void);
extern void ret_end(void);

int ret(int dummy){
	if(dummy){
		EMIT_LABEL("ret_start");
		return 0;
	}
	// we also copy the remaining part of the dummy branch, but we don't care (since we're returning)
	EMIT_LABEL("ret_end");
	return 0;
}

/**
 * Entry point: runs on SHM stack
 **/
__attribute__((constructor)) void ctor(void)
{
	LOG_INIT("/tmp/"MODULE_NAME".log");

	struct crt_params *params = &gParams;
	memset(params, 0x00, sizeof(*params));

	// get pid (use syscall to avoid libc pid caching)
	params->pid = syscall(__NR_getpid);

	INFO("pid: %u", params->pid);

	DBG("semget");
	if((params->sema = semget(params->pid, 1, S_IRWXO)) < 0){
		PERROR("semget");
		return;
	}

	DBG("shmget");
	struct injcode_bearing *br = acquire_shm(params->pid);
	if(!br){
		PERROR("shmat");
		return;
	}

	size_t br_size = SIZEOF_BR(*br);
	void *localBr = malloc(br_size);
	if(!localBr){
		PERROR("malloc");
		return;
	}
	memcpy(localBr, br, br_size);

	params->mem = localBr;

	// workaround for old uClibc (see http://lists.busybox.net/pipermail/uclibc/2009-October/043122.html)
	// https://github.com/kraj/uClibc/commit/cfa1d49e87eae4d46e0f0d568627b210383534f3
	#ifdef UCLIBC_OLD
	{
		void *h_libpthread = dlopen(PTHREAD_LIBRARY_NAME, RTLD_LAZY | RTLD_NOLOAD);
		if(h_libpthread == NULL){
			PERROR("dlopen");
			return;
		}

		DBG("__pthread_initialize_minimal");
		void (*pfnInitializer)() = dlsym(h_libpthread, "__pthread_initialize_minimal");
		if(pfnInitializer != NULL){
			pfnInitializer();
		}

		// once we have initialized, overwrite the function with a return
		void *ptrPage = PAGEALIGN(pfnInitializer);
		size_t pageSize = getpagesize();
		if(mprotect(ptrPage, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC) < 0){
			PERROR("mprotect");
			return;
		}
		hexdump(&ret_start, PTRDIFF(&ret_end, &ret_start));
		memcpy(ptrPage, &ret_start, PTRDIFF(&ret_end, &ret_start));
		if(mprotect(ptrPage, pageSize, PROT_READ | PROT_EXEC) < 0){
			PERROR("mprotect");
			return;
		}
	}
	#endif


	DBG("pthread_create");
	if(pthread_create(&br->user_tid, NULL, real_entry, params) < 0){
		PERROR("pthread_create");
		return;
	}
	shmdt(br);

	// notify thread is ready to be awaited
	DBG("semop");
	if(sema_op(params->sema, EZ_SEM_LIBCTL, -1) < 0){
		PERROR("semop");
	}
}


/**
 * User code: runs on mmap'd stack
 **/
void *real_entry(void *arg) {
	struct crt_params *params = (struct crt_params *)arg;

	struct injcode_bearing *br = (struct injcode_bearing *)(params->mem);

	// prepare argv
	char **dynPtr = (char **)((char *)br + sizeof(*br));
	char *dynStr = (char *)dynPtr + (sizeof(char *) * br->argc);

	dynStr += STRSZ(dynStr); // skip libdl.so name
	dynStr += STRSZ(dynStr); // skip libpthread.so name

	for(int i=0; i<br->argc; i++){
		*(dynPtr++) = dynStr;
		dynStr += strlen(dynStr) + 1;
	}

#ifdef DEBUG
	hexdump(br, SIZEOF_BR(*br));
#endif

	crt_userinit(br);

	DBG("ret");
	LOG_FINI();

	free(br);
	return (void *)EXIT_SUCCESS;
}

