#ifndef __EZINJECT_COMPAT_H
#define __EZINJECT_COMPAT_H

#include "config.h"

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


#ifndef PTRACE_SETOPTIONS
#define PTRACE_SETOPTIONS 0x4200
#endif

#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD 1
#endif

#ifdef EZ_TARGET_WINDOWS
#define SIGSTOP 0
#define SIGTRAP 0
#endif

#if defined(EZ_TARGET_FREEBSD) || defined(EZ_TARGET_DARWIN)
#define __NR_getpid SYS_getpid
#define __NR_shmget SYS_shmget
#define __NR_shmat SYS_shmat
#define __NR_shmdt SYS_shmdt
#define __NR_write SYS_write
#define __NR_kill SYS_kill
#endif

#if defined(EZ_TARGET_LINUX)
  #if !defined(__NR_mmap2) && !defined(__NR_mmap)
  #error "Unsupported platform"
  #elif !defined(__NR_mmap2)
  #define __NR_mmap2 __NR_mmap
  #endif
#endif // EZ_TARGET_LINUX


#endif