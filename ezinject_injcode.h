#include <sys/types.h>
#include <linux/limits.h>

#define INJ_PATH_MAX 128

struct injcode_bearing
{
	void *mapped_mem;
	void (*libc_dlopen_mode)(const char *name, int mode);
	long (*libc_syscall)(long number, ...);
	int (*libc_shmget)(key_t key, size_t size, int shmflg);
	void *(*libc_shmat)(int shmid, const void *shmaddr, int shmflg);
	int (*libc_shmdt)(const void *shmaddr);
	char libname[INJ_PATH_MAX];
};

extern __attribute__((naked, noreturn)) void injected_code();
extern __attribute__((naked)) void injected_code_end(void);
