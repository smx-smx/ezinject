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

#define UNUSED(x) (void)(x)

extern void lib_preinit(struct injcode_user *user);
extern int lib_main(int argc, char *argv[]);

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

/**
 * Entry point: runs on SHM stack
 **/
__attribute__((constructor)) void ctor(void)
{
	struct crt_params *params = &gParams;
	memset(params, 0x00, sizeof(*params));

	// get pid (use syscall to avoid libc pid caching)
	params->pid = syscall(__NR_getpid);
	
	INFO("pid: %zu", params->pid);

	if((params->sema = semget(params->pid, 2, S_IRWXO)) < 0){
		PERROR("semget");
		return;
	}

	struct injcode_bearing *br = acquire_shm(params->pid);
	if(!br){
		PERROR("shmat");
		return;
	}

	params->mem = br;
	pthread_create(&br->user_tid, NULL, real_entry, params);
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

	lib_preinit(&br->user);
	lib_main(br->argc, br->argv);

	shmdt(params->mem);

	DBG("semop");
	// trigger dlclose (caller will wait for us)
	if(sema_op(params->sema, EZ_SEM_LIBCTL, -1) < 0){
		perror("semop");
		return (void *)EXIT_FAILURE;
	}
	return (void *)EXIT_SUCCESS;
}

