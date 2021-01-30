#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#include "config.h"

#if defined(EZ_TARGET_LINUX)
	#if !defined(HAVE_SHM_SYSCALLS)
	#include <asm-generic/ipc.h>
	#endif
#elif defined(EZ_TARGET_FREEBSD)
	#include <sys/sysproto.h>
#endif

#if !defined(EZINJECT_INJCODE) && defined(HAVE_SYS_SHM_H)
#include <sys/shm.h>
#endif

#include <sys/ipc.h>

#include "ezinject_compat.h"

#if !defined(USE_ANDROID_ASHMEM)

#ifdef EZINJECT_INJCODE
#include "ezinject_injcode.h"
#define SYSCALL br->libc_syscall
#else
#define INLINE
#define SYSCALL syscall
#define inj_dchar
#endif

INLINE int shmget(BR_PARAM key_t key, size_t size, int shmflg){
#if defined(EZ_TARGET_LINUX)
	#if defined(HAVE_SHM_SYSCALLS)
	return (int)SYSCALL(__NR_shmget, key, size, shmflg);
	#else
	return (int)SYSCALL(__NR_ipc, IPCCALL(0, SHMGET), key, size, shmflg);
	#endif
#elif defined(EZ_TARGET_FREEBSD)
	return (int)SYSCALL(SYS_shmget, key, size, shmflg);
#endif
}

INLINE void *shmat(BR_PARAM int shmid, const void *shmaddr, int shmflg){
#if defined(EZ_TARGET_LINUX)
	#ifdef HAVE_SHM_SYSCALLS
	return (void *)SYSCALL(__NR_shmat, shmid, shmaddr, shmflg);
	#else
	return (void *)SYSCALL(__NR_ipc, IPCCALL(0, SHMAT), shmid, shmflg, &shmaddr, shmaddr);
	// return (ret > -(unsigned long)pageSize) ? (void *)ret : (void *)shmaddr;
	#endif
#elif defined(EZ_TARGET_FREEBSD)
	return (void *)(long)SYSCALL(SYS_shmat, shmid, shmaddr, shmflg);
#endif
}

INLINE int shmdt(BR_PARAM const void *shmaddr){
#if defined(EZ_TARGET_LINUX)
	#ifdef HAVE_SHM_SYSCALLS
	return (int)SYSCALL(__NR_shmdt, shmaddr);
	#else
	return (int)SYSCALL(__NR_ipc, IPCCALL(0, SHMDT), shmaddr);
	#endif
#elif defined(EZ_TARGET_FREEBSD)
	return (int)SYSCALL(SYS_shmdt, shmaddr);
#endif
}

#if !defined(EZINJECT_INJCODE) && !defined(EZ_TARGET_DARWIN)
#include <stdarg.h>

#ifndef IPC_64
#define IPC_64 0x100
#endif

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
#if defined(EZ_TARGET_LINUX)
	#ifdef HAVE_SHM_SYSCALLS
	int r = syscall(__NR_shmctl, id, IPC_CMD(cmd), buf);
	#else
	int r = syscall(__NR_ipc, IPCCALL(0, SHMCTL), id, IPC_CMD(cmd), 0, buf, 0);
	#endif
#elif defined(EZ_TARGET_FREEBSD)
	int r = syscall(SYS_shmctl, id, IPC_CMD(cmd), buf);
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