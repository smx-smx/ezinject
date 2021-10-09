/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include "config.h"

#include <sys/syscall.h>

#ifdef EZ_TARGET_FREEBSD
#include <sys/sysproto.h>
#endif

#include <sys/mman.h>

#include "ezinject.h"
#include "log.h"

uintptr_t remote_pl_alloc(struct ezinj_ctx *ctx, size_t mapping_size){
	uintptr_t result = RSCALL6(ctx, SYS_mmap,
		NULL, mapping_size,
		PROT_READ | PROT_WRITE | PROT_EXEC,
		MAP_ANONYMOUS, -1, 0
	);
	if(result == (uintptr_t)MAP_FAILED){
		return 0;
	}
	return result;
}

EZAPI remote_pl_free(struct ezinj_ctx *ctx, uintptr_t remote_shmaddr){
	struct injcode_bearing *br = (struct injcode_bearing *)ctx->mapped_mem.local;
	return (intptr_t) CHECK(RSCALL2(ctx, SYS_munmap, ctx->mapped_mem.remote, br->mapping_size));
}
