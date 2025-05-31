/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include "ezinject.h"
#include "win32_syscalls.h"
#include "log.h"

uintptr_t remote_pl_alloc(struct ezinj_ctx *ctx, size_t mapping_size){
	return (uintptr_t)CHECK(RSCALL4(ctx, __NR_mmap,
		NULL, // lpAddress
		mapping_size, // dwSize
		MEM_COMMIT | MEM_RESERVE, // flAllocationType
		PAGE_EXECUTE_READWRITE // flProtect
	));
}

EZAPI remote_pl_free(struct ezinj_ctx *ctx, uintptr_t remote_shmaddr){
	struct injcode_bearing *br = (struct injcode_bearing *)ctx->mapped_mem.local;
	return (uintptr_t)CHECK(RSCALL3(ctx, __NR_munmap,
		remote_shmaddr, // lpAddress
		br->mapping_size, // dwSize
		MEM_RELEASE // dwFreeType
	));
}
