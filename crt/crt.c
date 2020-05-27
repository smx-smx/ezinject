#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <sched.h>
#include <unistd.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <asm/unistd.h>

#include "ezinject_injcode.h"

#include "log.h"

#ifdef DEBUG
#include "util.h"
#endif

#define UNUSED(x) (void)(x)

extern void lib_preinit(struct injcode_user *user);
extern int lib_main(int argc, char *argv[]);

int real_entry(void *arg);

__attribute__((constructor)) void entry(void)
{
	pid_t pid = syscall(__NR_getpid);
	uintptr_t stack_base;
	size_t stack_size;
	if(get_stack(pid, &stack_base, &stack_size) < 0){
		ERR("Cannot retrive stack size");
		return;
	}
	INFO("Stack size: %zu", stack_size);

	void *newstack = mmap(0, stack_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if(newstack == MAP_FAILED){
		PERROR("Failed to allocate new stack");
		return;
	}

	void *newstack_top = (void *)((uintptr_t)newstack + stack_size);

	// clone again, with new stack
	clone(real_entry, newstack_top, CLONE_VM|CLONE_SIGHAND|CLONE_THREAD, NULL);
}

int real_entry(void *arg) {
	UNUSED(arg);

	/**
	 * getpid() from uClibc is broken, and returns the thread id instead of the process id
	 * so we use the syscall directly
	 */
	pid_t pid = syscall(__NR_getpid);
	int shm_id = shmget(pid, MAPPINGSIZE, 0);
	if(shm_id < 0){
		fprintf(stderr, "shmget(%u): %s\n", pid, strerror(errno));
		return EXIT_FAILURE;
	}
	void *mem = shmat(shm_id, NULL, SHM_RDONLY);
	if(mem == MAP_FAILED){
		perror("shmat");
		return EXIT_FAILURE + 1;
	}

	int sem_id = semget(pid, 1, 0);
	if(sem_id < 0){
		perror("semget");
		return EXIT_FAILURE + 2;
	}

	// copy the struct locally
	struct injcode_bearing *br = (struct injcode_bearing *)mem;

	unsigned int memSize = sizeof(*br) + br->dyn_size;
	uint8_t *localMem = malloc(memSize);
	memcpy(localMem, br, memSize);

	// prepare argv
	char **dynPtr = (char **)((char *)localMem + sizeof(*br));
	char *dynStr = (char *)dynPtr + (sizeof(char *) * br->argc);
#ifdef HAVE_DL_LOAD_SHARED_LIBRARY
	dynStr += strlen(dynStr) + 1; // skip libdl.so name
#endif

	for(int i=0; i<br->argc; i++){
		*(dynPtr++) = dynStr;
		dynStr += strlen(dynStr) + 1;
	}

#ifdef DEBUG
	hexdump(localMem, memSize);
#endif
	shmdt(mem);

	// signal ezinject to close IPC
	struct sembuf sem_op = {
		.sem_num = 0,
		.sem_op = -1,
		.sem_flg = 0
	};
	if(semop(sem_id, &sem_op, 1) < 0){
		perror("semop");
		return EXIT_FAILURE + 3;
	}

	// switch to localMem
	br = (struct injcode_bearing *)localMem;

	lib_preinit(&br->user);
	lib_main(br->argc, br->argv);
	
	free(localMem);
	return 0;
}