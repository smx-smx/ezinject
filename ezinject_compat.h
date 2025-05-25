/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
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
#define __NR_mmap2 SYS_mmap
#define __NR_munmap SYS_munmap
#define __NR_open SYS_open
#define __NR_close SYS_close
#endif

#if defined(EZ_TARGET_LINUX)
  #include <sys/syscall.h>
  #if !defined(__NR_mmap2) && !defined(__NR_mmap)
  #error "Unsupported platform"
  #elif !defined(__NR_mmap2)
  #define __NR_mmap2 __NR_mmap
  #endif
#endif // EZ_TARGET_LINUX

#if __BIG_ENDIAN__
# define ez_htonll(x) (x)
# define ez_ntohll(x) (x)
#else
# define ez_htonll(x) (((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
# define ez_ntohll(x) (((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
  #define DLLEXPORT __declspec(dllexport)
#else
  #define DLLEXPORT __attribute__((visibility("default")))
#endif


#ifdef EZ_TARGET_WINDOWS
#else
#define WINAPI
#endif

#endif
