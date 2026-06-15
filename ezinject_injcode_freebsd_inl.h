#ifndef __EZINJECT_INJCODE_PLATFORM_FREEBSD_H
#define __EZINJECT_INJCODE_PLATFORM_FREEBSD_H

#include <stdint.h>
#include <sys/types.h>

struct bearing_platform {
	struct {
		void *(*fptr)(const char *name, int mode);
		void *got;
		void *self;
	} libc_dlopen;
};

struct call_platform {
	struct {
		long (*fptr)(long number, ...);
		void *got;
		void *self;
	} libc_syscall;
};

#endif
