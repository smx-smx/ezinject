#ifndef __EZINJECT_INJCODE_PLATFORM_DARWIN_H
#define __EZINJECT_INJCODE_PLATFORM_DARWIN_H

#include <stdint.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/thread_act.h>

struct bearing_platform {
	thread_act_t mach_thread;
	pthread_t tid;

	struct {
		void *(*fptr)(const char *name, int mode);
		void *got;
		void *self;
	} libc_dlopen;

	int (*pthread_create)(pthread_t *restrict thread,
		const pthread_attr_t *restrict attr,
		typeof(void *(void *)) *start_routine,
		void *restrict arg);
	int (*pthread_join)(pthread_t thread, void **value_ptr);
	int (*pthread_create_from_mach_thread)(
		pthread_t *thread,
		const pthread_attr_t *attr,
		void *(*start_routine)(void *), void *arg);
	pthread_t (*pthread_self)(void);
	int (*pthread_detach)(pthread_t thread);
	kern_return_t (*thread_terminate)(thread_act_t target_act);
	kern_return_t (*mach_port_allocate)
		(ipc_space_t        task,
		mach_port_right_t   right,
		mach_port_name_t    *name);
	thread_act_t (*mach_thread_self)(void);
	mach_port_t  (*task_self_trap)(void);
};

struct call_platform {
	struct {
		long (*fptr)(long number, ...);
		void *got;
		void *self;
	} libc_syscall;
};

#endif
