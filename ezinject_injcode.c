#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include "ezinject_injcode.h"

#define __RTLD_DLOPEN 0x80000000 /* glibc internal */
#define MAPPINGSIZE 4096

__attribute__((naked, noreturn)) void injected_code()
{
	struct injcode_bearing *br;
#if defined(__i386__) || defined(__amd64__)
	asm volatile("pop %0" : "=r"(br));
#elif defined(__arm__)
	asm volatile("pop {%0}" : "=r"(br));
#elif defined(__mips__)
 	asm volatile (
		 "lw %0, 0($sp)\n\t"
		 "addi $sp, $sp, 4\n\t"
		 : "=r" (br)
	);
#else
#error "Unsupported architecture"
#endif

	br->libc_dlopen_mode(br->libname, RTLD_NOW | __RTLD_DLOPEN);
	br->libc_shmdt(br->mapped_mem);
	br->libc_syscall(__NR_exit, 0);
}

__attribute__((naked)) void injected_code_end(void)
{

}
