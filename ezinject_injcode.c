#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <sys/syscall.h>

#include "config.h"
#include "ezinject_injcode.h"

#define __RTLD_DLOPEN 0x80000000 /* glibc internal */

__attribute__((naked, noreturn)) void injected_code()
{
	struct injcode_bearing *br;

#if defined(EZ_ARCH_I386) || defined(EZ_ARCH_AMD64)
	asm volatile("pop %0" : "=r"(br));
#elif defined(EZ_ARCH_ARM)
	asm volatile("pop {%0}" : "=r"(br));
#elif defined(EZ_ARCH_MIPS)
 	asm volatile (
		 "lw %0, 0($sp)\n\t"
		 "addi $sp, $sp, 4\n\t"
		 : "=r" (br)
	);
#else
#error "Unsupported architecture"
#endif

	// dynStr points to first argument, argv[0], which is the library to load
	char *dynStr = (char *)br + sizeof(*br) + (sizeof(char *) * br->argc);
	br->lib_handle = br->libc_dlopen_mode(dynStr, RTLD_NOW | __RTLD_DLOPEN);
	br->libc_syscall(__NR_exit, 0);
}

__attribute__((naked)) void injected_code_end(void)
{

}
