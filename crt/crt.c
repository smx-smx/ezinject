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
#include "ezinject_util.h"
#endif

#ifndef MODULE_NAME
#define MODULE_NAME "userlib"
#endif

#define UNUSED(x) (void)(x)

#ifdef UCLIBC_OLD
#include "crt_uclibc.c"
#endif

#include "crt.h"

extern int crt_userinit(struct injcode_bearing *br);

void* crt_user_entry(void *arg);

__attribute__((constructor)) void ctor(void)
{
	LOG_INIT("/tmp/"MODULE_NAME".log");
	INFO("library loaded!");
}


int crt_init(struct injcode_bearing *br){
	INFO("initializing");

	// copy local br (excluding code and stack)
	size_t br_size = SIZEOF_BR(*br);
	struct injcode_bearing *local_br = malloc(br_size);
	if(!local_br){
		PERROR("malloc");
		return -2;
	}
	memcpy(local_br, br, br_size);

	struct crt_ctx ctx = {
		.shared_br = br,
		.local_br = local_br
	};

	// workaround for old uClibc (see http://lists.busybox.net/pipermail/uclibc/2009-October/043122.html)
	// https://github.com/kraj/uClibc/commit/cfa1d49e87eae4d46e0f0d568627b210383534f3
	#ifdef UCLIBC_OLD
	uclibc_fixup_pthread();
	#endif

	DBG("crt_thread_create");
	// user thread must run against the local copy of br
	if(crt_thread_create(&ctx, crt_user_entry) < 0){
		ERR("crt_thread_create failed");
		return -1;
	}
	DBG("crt_thread_notify");
	// notification must be done over the (possibly shared) br
	if(crt_thread_notify(&ctx) < 0){
		ERR("crt_thread_notify failed");
		return -1;
	}
	return 0;
}


/**
 * User code: runs on mmap'd stack
 **/
void *crt_user_entry(void *arg) {
	struct injcode_bearing *br = arg;

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

