#include "config.h"

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <sched.h>
#include <pthread.h>
#include <unistd.h>
#ifdef HAVE_SYS_SHM_H
#include <sys/shm.h>
#endif
#ifdef EZ_TARGET_LINUX
#include <sys/prctl.h>
#endif
#ifdef EZ_TARGET_POSIX
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#endif
#ifdef EZ_TARGET_FREEBSD
#include <sys/sysproto.h>
#endif
#ifdef EZ_TARGET_LINUX
#include <asm/unistd.h>
#endif

#ifdef EZ_TARGET_WINDOWS
#include <windows.h>
#endif

#include <sys/stat.h>
#include <fcntl.h>

#include <pthread.h>
#include <dlfcn.h>

#include "ezinject.h"
#include "ezinject_compat.h"
#include "ezinject_common.h"
#include "ezinject_injcode.h"

#include "log.h"

#ifdef DEBUG
#include "util.h"
#endif

#ifndef MODULE_NAME
#define MODULE_NAME "userlib"
#endif

#define UNUSED(x) (void)(x)

#ifdef UCLIBC_OLD
#include "crt_uclibc.c"
#endif

extern int crt_userinit(struct injcode_bearing *br);

struct crt_params {
	pid_t pid;
	int sema;
	struct injcode_bearing *br;
};

static struct crt_params gParams;

void* real_entry(void *arg);

__attribute__((constructor)) void ctor(void)
{
	LOG_INIT("/tmp/"MODULE_NAME".log");
	INFO("library loaded!");
}


int crt_init(struct injcode_bearing *br){
	INFO("initializing");

	struct crt_params *params = &gParams;
	memset(params, 0x00, sizeof(*params));

	// get pid (use syscall to avoid libc pid caching)
	#if defined(EZ_TARGET_LINUX)
	params->pid = syscall(__NR_getpid);
	#elif defined(EZ_TARGET_FREEBSD)
	params->pid = syscall(SYS_getpid);
	#elif defined(EZ_TARGET_WINDOWS)
	params->pid = GetCurrentProcessId();
	#else
	#error "Unsupported target"
	#endif

	INFO("pid: %u", params->pid);

	// copy local br (excluding code and stack)
	size_t br_size = SIZEOF_BR(*br);
	void *localBr = malloc(br_size);
	if(!localBr){
		PERROR("malloc");
		return -2;
	}
	memcpy(localBr, br, br_size);
	params->br = (struct injcode_bearing *)localBr;

	// workaround for old uClibc (see http://lists.busybox.net/pipermail/uclibc/2009-October/043122.html)
	// https://github.com/kraj/uClibc/commit/cfa1d49e87eae4d46e0f0d568627b210383534f3
	#ifdef UCLIBC_OLD
	uclibc_fixup_pthread();
	#endif


#if defined(EZ_TARGET_POSIX)
	DBG("pthread_create");
	if(pthread_create(&br->user_tid, NULL, real_entry, params) < 0){
		PERROR("pthread_create");
		return -3;
	}

	DBG("sending pthread signal");
	pthread_mutex_lock(&br->mutex);
	{
		br->loaded_signal = 1;
		pthread_cond_signal(&br->cond);
	}
	pthread_mutex_unlock(&br->mutex);
#elif defined(EZ_TARGET_WINDOWS)
	br->hThread = CreateThread(
		NULL,
		0,
		real_entry,
		params,
		0,
		&br->user_tid
	);
	if(br->hThread == INVALID_HANDLE_VALUE){
		PERROR("CreateThread");
		return -3;
	}
	if(SetEvent(br->hEvent) == FALSE){
		PERROR("SetEvent");
		return -4;
	}
#endif
	return 0;
}


/**
 * User code: runs on mmap'd stack
 **/
void *real_entry(void *arg) {
	struct crt_params *params = (struct crt_params *)arg;
	struct injcode_bearing *br = params->br;

	// prepare argv
	char **dynPtr = &br->argv[0];
	
	char *stbl = BR_STRTBL(br) + br->argv_offset;
	for(int i=0; i<br->argc; i++){
		char *arg = NULL;
		STRTBL_FETCH(stbl, arg);
		*(dynPtr++) = arg;
	}

#ifdef DEBUG
	hexdump(br, SIZEOF_BR(*br));
#endif

	enum userlib_return_action result;

	crt_userinit(br);
	if(br->user.persist){
		result = userlib_persist;
	} else {
		result = userlib_unload;
	}

	DBG("ret");
	LOG_FINI();

	free(br);
	return (void *)result;
}

