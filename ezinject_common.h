/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#ifndef __EZINJECT_COMMON_H
#define __EZINJECT_COMMON_H

#include <unistd.h>

#define UNUSED(x) (void)(x)
#define ALIGNMSK(y) ((y)-1)

#ifdef ALIGN
#undef ALIGN
#endif

#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define ALIGN(x, y) VPTR((UPTR(x) + ALIGNMSK(y)) & ~ALIGNMSK(y))
#define WORDALIGN(x) ALIGN(x, sizeof(void *))
#define PAGEALIGN(x)  ALIGN(x, getpagesize())

#define VPTR(x) ((void *)(x))
#define UPTR(x) ((uintptr_t)(x))
#define PTRADD(a, b) ( UPTR(a) + UPTR(b) )
#define PTRDIFF(a, b) ( UPTR(a) - UPTR(b) )

#define STRSZ(x) (strlen(x) + 1)

enum ezinj_str_id {
#ifdef EZ_TARGET_LINUX
	// payload filename.
	// *MUST* always be the first entry
	EZSTR_PL_FILENAME = 0,
#endif
	EZSTR_API_LIBDL,
	EZSTR_API_LIBPTHREAD,
#if defined(EZ_TARGET_POSIX)
	EZSTR_API_DLERROR,
	EZSTR_API_PTHREAD_MUTEX_INIT,
	EZSTR_API_PTHREAD_MUTEX_LOCK,
	EZSTR_API_PTHREAD_MUTEX_UNLOCK,
	EZSTR_API_COND_INIT,
	EZSTR_API_COND_WAIT,
#elif defined(EZ_TARGET_WINDOWS)
	EZSTR_API_CREATE_EVENT,
	EZSTR_API_CREATE_THREAD,
	EZSTR_API_CLOSE_HANDLE,
	EZSTR_API_WAIT_FOR_SINGLE_OBJECT,
	EZSTR_API_GET_EXIT_CODE_THREAD,
#endif
	EZSTR_API_CRT_INIT,
	EZSTR_ARGV0,
	EZSTR_MAX_DEFAULT
};

struct ezinj_str {
	unsigned int id;
	char *str;
};

#define BR_STRTBL(br) ((struct ezinj_str *)((char *)br + sizeof(*br) + (sizeof(char *) * br->argc)))
#define STR_DATA(entry) ((entry)->str)


#endif
