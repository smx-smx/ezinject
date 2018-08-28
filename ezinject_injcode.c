#include <sys/shm.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <fcntl.h>
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
#else
#error "Unsupported architecture"
#endif

	br->libc_dlopen_mode(br->libname, RTLD_NOW | __RTLD_DLOPEN);

	pid_t pid = br->libc_syscall(__NR_getpid);
	int shm_id = br->libc_syscall(__NR_shmget, pid, MAPPINGSIZE, S_IRWXO);
	void *mem = (void *)br->libc_syscall(__NR_shmat, shm_id, 0);
	br->libc_syscall(__NR_shmdt, mem);

	br->libc_syscall(__NR_exit, 0);
}

__attribute__((naked)) void injected_code_end(void)
{

}
