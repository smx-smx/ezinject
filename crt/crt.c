/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <sched.h>
#include <pthread.h>
#include <unistd.h>

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

	// workaround for old uClibc (see http://lists.busybox.net/pipermail/uclibc/2009-October/043122.html)
	// https://github.com/kraj/uClibc/commit/cfa1d49e87eae4d46e0f0d568627b210383534f3
	#ifdef UCLIBC_OLD
	uclibc_fixup_pthread();
	#endif

	DBG("crt_thread_create");
	// user thread must run against the local copy of br
	if(crt_thread_create(br, crt_user_entry) < 0){
		ERR("crt_thread_create failed");
		return -1;
	}
	DBG("crt_thread_notify");
	// notification must be done over the (possibly shared) br
	if(crt_thread_notify(br) < 0){
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

	int result = crt_userinit(br);

	DBG("ret");
	LOG_FINI();

	return (void *)result;
}

