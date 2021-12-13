/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include "ezinject_injcode.h"
#include <link.h>

//#define SIMULATE_EGLIBC_BUG

INLINE void *inj_get_libdl(struct injcode_ctx *ctx){
	struct injcode_bearing *br = ctx->br;

	char *libdl_name = STR_DATA(BR_STRTBL(br));

#if defined(HAVE_LIBC_DLOPEN_MODE)
	struct link_map *libdl = (struct link_map *) br->libc_dlopen(libdl_name, RTLD_NOW | __RTLD_DLOPEN);
#elif defined(HAVE_LIBC_DL_OPEN)
	struct link_map *libdl = (struct link_map *) br->libc_dlopen(libdl_name, RTLD_NOW | __RTLD_DLOPEN, NULL);
#else
#error "Unsupported build flags"
#endif

	if(libdl == NULL){
		return NULL;
	}
#ifdef SIMULATE_EGLIBC_BUG
	return NULL;
#else
	return (void *)libdl->l_addr;
#endif
}
