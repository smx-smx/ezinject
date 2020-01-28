#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <sys/syscall.h>

#include "config.h"
#include "ezinject_arch.h"
#include "ezinject_injcode.h"

#define ALIGN(x) ((void *)(((uintptr_t)x + MEMALIGN) & ALIGNMSK))
#define __RTLD_DLOPEN 0x80000000 /* glibc internal */

#ifdef HAVE_CLONE_IO
#define CLONE_FLAGS (CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_PARENT|CLONE_THREAD|CLONE_IO)
#else
#define CLONE_FLAGS (CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_PARENT|CLONE_THREAD)
#endif

//#define syscall_offset offsetof(struct injcode_bearing, libc_syscall)

#define STR2(X) #X
#define STR(X) STR2(X)

#define EMIT_LABEL(name) \
	asm volatile( \
		".globl "STR(name)"\n" \
		STR(name)":\n" \
	)

__attribute__((naked)) void injected_code_start(void)
{
}

__attribute__((naked, noreturn)) void injected_sc(){
	EMIT_LABEL("injected_sc_start");
	EMIT_SC();
	EMIT_LABEL("injected_sc_end");
}

__attribute__((naked, noreturn)) void injected_clone(){
	EMIT_LABEL("injected_clone_entry");

	struct injcode_bearing *br;
	EMIT_POP(br);

	int (*pfnChild)(void *arg);
	EMIT_POP(pfnChild);

	void *clone_stack;
	EMIT_POP(clone_stack);

	br->libc_clone(pfnChild, clone_stack, CLONE_FLAGS, br);
}

int clone_fn(void *arg){
	struct injcode_bearing *br = (struct injcode_bearing *)arg;
	char *dynStr = (char *)br + sizeof(*br) + (sizeof(char *) * br->argc);
	br->lib_handle = br->libc_dlopen_mode(dynStr, RTLD_NOW | __RTLD_DLOPEN);
	return 0;
}

__attribute__((naked)) void injected_code_end(void)
{
}