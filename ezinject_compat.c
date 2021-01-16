#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#include "config.h"

#include "ezinject_compat.h"

#if !defined(USE_ANDROID_ASHMEM)

#ifdef EZINJECT_INJCODE
#include "ezinject_injcode.h"
#define SYSCALL br->libc_syscall
#else
#define INLINE
#define SYSCALL syscall
#define PL_DBG
#endif

INLINE int shmget(BR_PARAM key_t key, size_t size, int shmflg){
#if defined(HAVE_SHM_SYSCALLS)
	return SYSCALL(__NR_shmget, key, size, shmflg);
#else
	return SYSCALL(__NR_ipc, IPCCALL(0, SHMGET), key, size, fhmflg)
#endif
}

INLINE void *shmat(BR_PARAM int shmid, const void *shmaddr, int shmflg){
	#ifdef HAVE_SHM_SYSCALLS
	return SYSCALL(__NR_shmat, shmid, shmaddr, shmflg);
	#else
	long ret = SYSCALL(__NR_ipc, IPCCALL(0, SHMAT), shmid, shmflg, &shmaddr, shmaddr);
	return (ret > -(unsigned long)SHMLBA) ? (void *)ret : (void *)shmaddr;
	#endif
}

INLINE int shmdt(BR_PARAM const void *shmaddr){
	#ifdef HAVE_SHM_SYSCALLS
	return SYSCALL(__NR_shmdt, shmaddr);
	#else
	return SYSCALL(__NR_ipc, IPCCALL(0, SHMDR), shmaddr);
	#endif
}

#ifndef EZINJECT_INJCODE
#include <stdarg.h>

#define IPC_CMD(cmd) (((cmd) & ~IPC_TIME64) | IPC_64)
#define IPC_TIME64 (IPC_STAT & 0x100)
#define SEM_UNDO	0x1000
#define GETPID		11
#define GETVAL		12
#define GETALL		13
#define GETNCNT		14
#define GETZCNT		15
#define SETVAL		16
#define SETALL		17

#define SEM_STAT (18 | (IPC_STAT & 0x100))
#define SEM_INFO 19
#define SEM_STAT_ANY (20 | (IPC_STAT & 0x100))

/** ported from musl **/

union semun {
	int val;
	struct semid_ds *buf;
	unsigned short *array;
};

int semctl(int id, int num, int cmd, ...) {
	union semun arg = {0};
	va_list ap;
	switch (cmd & ~IPC_TIME64) {
	case SETVAL: case GETALL: case SETALL: case IPC_SET:
	case IPC_INFO: case SEM_INFO:
	case IPC_STAT & ~IPC_TIME64:
	case SEM_STAT & ~IPC_TIME64:
	case SEM_STAT_ANY & ~IPC_TIME64:
		va_start(ap, cmd);
		arg = va_arg(ap, union semun);
		va_end(ap);
	}
#if IPC_TIME64
	struct semid_ds out, *orig;
	if (cmd&IPC_TIME64) {
		out = (struct semid_ds){0};
		orig = arg.buf;
		arg.buf = &out;
	}
#endif
#ifdef SYSCALL_IPC_BROKEN_MODE
	struct semid_ds tmp;
	if (cmd == IPC_SET) {
		tmp = *arg.buf;
		tmp.sem_perm.mode *= 0x10000U;
		arg.buf = &tmp;
	}
#endif

#ifdef HAVE_SHM_SYSCALLS
	int r = syscall(__NR_semctl, id, num, IPC_CMD(cmd), arg.buf);
#else
	int r = syscall(__NR_ipc, IPCCALL(0, SEMCTL), id, num, IPC_CMD(cmd), &arg.buf);
#endif

#ifdef SYSCALL_IPC_BROKEN_MODE
	if (r >= 0) switch (cmd | IPC_TIME64) {
	case IPC_STAT:
	case SEM_STAT:
	case SEM_STAT_ANY:
		arg.buf->sem_perm.mode >>= 16;
	}
#endif
#if IPC_TIME64
	if (r >= 0 && (cmd&IPC_TIME64)) {
		arg.buf = orig;
		*arg.buf = out;
		IPC_HILO(arg.buf, sem_otime);
		IPC_HILO(arg.buf, sem_ctime);
	}
#endif
	return r;
}

int shmctl(int id, int cmd, struct shmid_ds *buf) {
#if IPC_TIME64
	struct shmid_ds out, *orig;
	if (cmd&IPC_TIME64) {
		out = (struct shmid_ds){0};
		orig = buf;
		buf = &out;
	}
#endif
#ifdef SYSCALL_IPC_BROKEN_MODE
	struct shmid_ds tmp;
	if (cmd == IPC_SET) {
		tmp = *buf;
		tmp.shm_perm.mode *= 0x10000U;
		buf = &tmp;
	}
#endif
#ifdef HAVE_SHM_SYSCALLS
	int r = syscall(__NR_shmctl, id, IPC_CMD(cmd), buf);
#else
	int r = syscall(__NR_ipc, IPCCALL(0, SHMCTL), id, IPC_CMD(cmd), 0, buf, 0);
#endif
#ifdef SYSCALL_IPC_BROKEN_MODE
	if (r >= 0) switch (cmd | IPC_TIME64) {
	case IPC_STAT:
	case SHM_STAT:
	case SHM_STAT_ANY:
		buf->shm_perm.mode >>= 16;
	}
#endif
#if IPC_TIME64
	if (r >= 0 && (cmd&IPC_TIME64)) {
		buf = orig;
		*buf = out;
		IPC_HILO(buf, shm_atime);
		IPC_HILO(buf, shm_dtime);
		IPC_HILO(buf, shm_ctime);
	}
#endif
	return r;
}


#endif /* USE_ANDROID_ASHMEM */
#endif