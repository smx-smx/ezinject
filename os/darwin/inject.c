/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <stdint.h>

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#include <mach/mach.h>

#include "ezinject.h"
#include "log.h"

uintptr_t remote_pl_alloc(struct ezinj_ctx *ctx, size_t mapping_size){
	kern_return_t kr;

	uintptr_t address = 0;
	kr = vm_allocate(ctx->task, &address, mapping_size, TRUE);
	if(kr != KERN_SUCCESS){
		ERR("vm_allocate failed: %s", mach_error_string(kr));
		return 0;
	}

	if(address == 0){
		ERR("allocation failed");
		return 0;
	}

	kr = vm_protect(
		ctx->task,
		(vm_address_t)address,
		mapping_size,
		false,
		VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE | VM_PROT_COPY
	);
	if(kr != KERN_SUCCESS){
		ERR("vm_protect failed to set current page privs: %s", mach_error_string(kr));
		return 0;
	}
	return address;
}

EZAPI remote_pl_free(struct ezinj_ctx *ctx, uintptr_t remote_shmaddr){
	struct injcode_bearing *br = (struct injcode_bearing *)ctx->mapped_mem.local;
	kern_return_t kr = vm_deallocate(
		ctx->task,
		(vm_address_t)remote_shmaddr,
		br->mapping_size
	);
	if(kr != KERN_SUCCESS){
		ERR("vm_deallocate failed");
		return -1;
	}
	return 0;
}

EZAPI remote_call_prepare(struct ezinj_ctx *ctx, struct injcode_call *call){
	return 0;
}

