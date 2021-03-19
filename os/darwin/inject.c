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
	return 0;
}

EZAPI remote_call_prepare(struct ezinj_ctx *ctx, struct injcode_call *call){ return 0; }