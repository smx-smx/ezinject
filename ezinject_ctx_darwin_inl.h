#ifndef __EZINJECT_CTX_PLATFORM_DARWIN_H
#define __EZINJECT_CTX_PLATFORM_DARWIN_H

#include <mach/mach.h>

struct ctx_platform {
	task_t task;
	thread_t thread;
	uint8_t *saved_sc_data;
	ssize_t saved_sc_size;
	int force_mmap_syscall;
	ez_addr pthread_create_from_mach_thread;
	ez_addr pthread_create;
	ez_addr pthread_join;
	ez_addr pthread_detach;
	ez_addr pthread_self;
	ez_addr mach_thread_self;
	ez_addr task_self_trap;
	ez_addr mach_port_allocate;
	ez_addr thread_terminate;
};

#endif
