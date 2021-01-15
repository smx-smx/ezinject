#ifndef __EZINJECT_SHARED_H
#define __EZINJECT_SHARED_H

#ifndef HAVE_SHM_EXEC
#define	SHM_EXEC	0100000	/* execution access */
#endif

#ifndef HAVE_RTLD_NOLOAD
// dummy
#define RTLD_NOLOAD 0
#endif

#define IS_IGNORED_SIG(x) ((x) == SIGUSR1 || (x) == SIGUSR2 || (x) >= SIGRTMIN)

#ifndef PTRACE_SETOPTIONS
#define PTRACE_SETOPTIONS 0x4200
#endif

#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD 1
#endif

#include "config.h"
#include <sys/ipc.h>

#ifndef HAVE_SYS_SEM_H
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

#ifndef HAVE_SYS_SHM_H
int shmget(BR_PARAM key_t key, size_t size, int shmflg);
void *shmat(BR_PARAM int shmid, const void *shmaddr, int shmflg);
int shmdt(BR_PARAM const void *shmaddr);
int shmctl(int id, int cmd, struct shmid_ds *buf);
#endif

#endif /* EZINJECT_INJCODE */

#endif