#include <sys/syscall.h>
#include <dlfcn.h>
#include "ezinject_injcode.h"

#define __RTLD_DLOPEN 0x80000000 /* glibc internal */

__attribute__((naked, noreturn)) void injected_code(void)
{
	struct injcode_bearing *br;
#if defined(__i386__) || defined(__amd64__)
	asm volatile("pop %0" : "=r"(br));
#elif defined(__arm__)
	asm volatile("pop {%0}" : "=r"(br));
#else
#error "Unsupported architecture"
#endif

	br->libc_dlopen_mode(br->libname, RTLD_NOW | __RTLD_DLOPEN);

#if defined(__i386__)
	asm volatile("\n\
	mov %0, %%eax\n\
	xor %%ebx, %%ebx\n\
	int $0x80\n" : : "i"(__NR_exit));
#elif defined(__amd64__)
	asm volatile("\n\
	mov %0, %%rax\n\
	xor %%rdi, %%rdi\n\
	syscall\n" : : "i"(__NR_exit));
#elif defined(__arm__)
	asm volatile("\n\
	mov r7, %0\n\
	eor r0, r0\n\
	swi 0x0\n\
	" : : "i"(__NR_exit));

#else
#error "Unsupported architecture"
#endif
}

__attribute__((naked)) void injected_code_end(void)
{

}
