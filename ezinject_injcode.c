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

#ifdef HAVE_CLONE_IO
#define CLONE_FLAGS (CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_PARENT|CLONE_THREAD|CLONE_IO)
#else
#define CLONE_FLAGS (CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_PARENT|CLONE_THREAD)
#endif

#define EMIT_LABEL(name) \
	asm volatile( \
		".globl "name"\n" \
		name":\n" \
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
	int (*pfnChild)(void *arg);
	void *clone_stack;
	
	EMIT_POP(br);
	EMIT_POP(pfnChild);
	EMIT_POP(clone_stack);

	br->libc_clone(pfnChild, clone_stack, CLONE_FLAGS, br);
}

int clone_fn(void *arg){
	struct injcode_bearing *br = (struct injcode_bearing *)arg;
	// get argv[0], which is the library to load
	char *lib_name = (char *)br + sizeof(*br) + (sizeof(char *) * br->argc);

#if defined(HAVE_LIBC_DLOPEN_MODE)
#define __RTLD_DLOPEN 0x80000000 /* glibc internal */
	br->libc_dlopen(lib_name, RTLD_NOW | __RTLD_DLOPEN);
#elif defined(HAVE_DL_LOAD_SHARED_LIBRARY)
	struct dyn_elf *rpnt = NULL;
	for (rpnt = *(br->uclibc_sym_tables); rpnt && rpnt->next; rpnt = rpnt->next){
		continue;
	}
	br->libc_dlopen(RTLD_NOW, &rpnt, NULL, lib_name, 0);
#endif

	br->libc_syscall(__NR_exit, 0);
	
	// should never be reached, or we hit unexpected behaviour (we have an invalid return address)
	return 0;
}

__attribute__((naked)) void injected_code_end(void)
{
}