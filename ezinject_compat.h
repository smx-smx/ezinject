#ifndef __EZINJECT_COMPAT_H
#define __EZINJECT_COMPAT_H

#include "config.h"

#if !defined(HAVE_SHM_EXEC)
	#if defined(EZ_TARGET_LINUX)
	#define	SHM_EXEC	0100000	/* execution access */
	#else
	#define SHM_EXEC 0 // dummy
	#endif
#endif

#ifndef MAP_FAILED
#define MAP_FAILED (void *)-1
#endif

#ifndef HAVE_RTLD_NOLOAD
// dummy
#define RTLD_NOLOAD 0
#endif

#ifndef RTLD_DEEPBIND
// dummy
#define RTLD_DEEPBIND 0
#endif

#if defined(EZ_TARGET_DARWIN)
#define IS_IGNORED_SIG(x) ((x) == SIGUSR1 || (x) == SIGUSR2)
#elif defined(EZ_TARGET_WINDOWS)
#define IS_IGNORED_SIG(x) 0
#else
#define IS_IGNORED_SIG(x) ((x) == SIGUSR1 || (x) == SIGUSR2 || (x) >= SIGRTMIN)
#endif

#ifndef PTRACE_SETOPTIONS
#define PTRACE_SETOPTIONS 0x4200
#endif

#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD 1
#endif

#include "config.h"

#ifdef EZ_TARGET_WINDOWS
#define SIGSTOP 0
#define SIGTRAP 0
#endif

#ifndef EZ_TARGET_WINDOWS
#include <sys/ipc.h>


#ifndef HAVE_SYS_SHM_H
struct sembuf {
	unsigned short int sem_num;   /* semaphore number */
	short int sem_op;             /* semaphore operation */
	short int sem_flg;            /* operation flag */
};

struct shmid_ds {
	struct ipc_perm shm_perm;
	size_t shm_segsz;
	time_t shm_atime;
	time_t shm_dtime;
	time_t shm_ctime;
	pid_t shm_cpid;
	pid_t shm_lpid;
	unsigned long shm_nattch;
	unsigned long __pad1;
	unsigned long __pad2;
};
#endif

#ifdef EZINJECT_INJCODE
#include "ezinject_injcode.h"
#define BR_PARAM struct injcode_bearing *br,
#else
#define BR_PARAM

#if defined(HAVE_SYS_SHM_H) || defined(EZ_TARGET_ANDROID)
int shmget(BR_PARAM key_t key, size_t size, int shmflg);
void *shmat(BR_PARAM int shmid, const void *shmaddr, int shmflg);
int shmdt(BR_PARAM const void *shmaddr);
int shmctl(int id, int cmd, struct shmid_ds *buf);
#endif

#endif /* EZINJECT_INJCODE */

#if defined(EZ_TARGET_FREEBSD) || defined(EZ_TARGET_DARWIN)
#define __NR_getpid SYS_getpid
#define __NR_shmget SYS_shmget
#define __NR_shmat SYS_shmat
#define __NR_shmdt SYS_shmdt
#define __NR_write SYS_write
#define __NR_kill SYS_kill
#endif

#endif /* EZ_TARGET_WINDOWS */

#endif