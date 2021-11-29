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

#define ALIGN(x, y) VPTR((UPTR(x) + ALIGNMSK(y)) & ~ALIGNMSK(y))
#define TRUNCATE(x, y) VPTR((UPTR(x) & ~ALIGNMSK(y)))
#define WORDALIGN(x) ALIGN(x, sizeof(void *))
#define PAGEALIGN(x)  ALIGN(x, getpagesize())

#define VPTR(x) ((void *)(x))
#define UPTR(x) ((uintptr_t)(x))
#define PTRADD(a, b) ( UPTR(a) + UPTR(b) )
#define PTRDIFF(a, b) ( UPTR(a) - UPTR(b) )

#define STRSZ(x) (strlen(x) + 1)

#define BR_STRTBL(br) ((char *)br + sizeof(*br) + (sizeof(char *) * br->argc))
#define STR_ENTSIZE(entry) *(unsigned int *)(entry)
#define STR_NEXT(entry) (entry) + STR_ENTSIZE(entry)
#define STR_DATA(entry) ((char *)(entry)) + sizeof(unsigned int)

#define STRTBL_SKIP(stbl) stbl = STR_NEXT(stbl)

#define STRTBL_FETCH(stbl, out) do { \
	out = STR_DATA(stbl); \
	STRTBL_SKIP(stbl); \
} while(0)

#endif
