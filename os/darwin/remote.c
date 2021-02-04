#include <stdlib.h>

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <mach/mach.h>
#include <unistd.h>

#include "ezinject.h"

// overrides default MACHINE_ macros
#include "ezinject_arch.h"
#include "log.h"

EZAPI remote_attach(struct ezinj_ctx *ctx){
	pid_t 	pid;
	task_t	task;
	kern_return_t kr;
	
	kr = task_for_pid(mach_task_self(), ctx->target, &task);
	if(kr != KERN_SUCCESS){
		ERR("task_for_pid failed: %s", mach_error_string(kr));
		return -1;
	}
	thread_act_port_array_t thread_list;
	mach_msg_type_number_t thread_count;
	kr = task_threads(task, &thread_list, &thread_count);
	if(kr != KERN_SUCCESS){
		ERR("task_threads failed: %s", mach_error_string(kr));
		return -1;
	}

	if(thread_count < 1){
		ERR("no thread available");
		return -1;
	}
	ctx->task = task;
	ctx->thread = thread_list[0];

	return ptrace(PT_ATTACH, ctx->target, 0, 0);
}

EZAPI remote_detach(struct ezinj_ctx *ctx){
	return ptrace(PT_DETACH, ctx->target, 0, 0);
}

EZAPI remote_continue(struct ezinj_ctx *ctx, int signal){
	return ptrace(PT_CONTINUE, ctx->target, (caddr_t)1, signal);
}

EZAPI remote_step(struct ezinj_ctx *ctx, int signal){
	return ptrace(PT_STEP, ctx->target, (caddr_t)1, signal);
}

EZAPI remote_getregs(struct ezinj_ctx *ctx, regs_t *regs){
	mach_msg_type_number_t count = MACHINE_THREAD_STATE_COUNT;
	kern_return_t kr = thread_get_state(
		ctx->thread, MACHINE_THREAD_STATE,
		(thread_state_t)regs, &count
	);

	if(kr != KERN_SUCCESS){
		ERR("thread_get_state failed: %s", mach_error_string(kr));
		return -1;
	}
	
	return 0;
}

EZAPI remote_setregs(struct ezinj_ctx *ctx, regs_t *regs){
	mach_msg_type_number_t count = MACHINE_THREAD_STATE_COUNT;
	kern_return_t kr = thread_set_state(
		ctx->thread, MACHINE_THREAD_STATE,
		(thread_state_t)regs, count
	);
	
	if(kr != KERN_SUCCESS){
		ERR("thread_set_state failed: %s", mach_error_string(kr));
		return -1;
	}

	return 0;
}

EZAPI remote_read(struct ezinj_ctx *ctx, void *dest, uintptr_t source, size_t size){
	mach_msg_type_number_t read = 0;

	vm_offset_t dataPointer = NULL;
	kern_return_t kr = vm_read(
		ctx->task,
		(vm_address_t)source,
		(vm_size_t)size,
		(vm_offset_t *)&dataPointer,
		&read
	);
	if(kr != KERN_SUCCESS){
		ERR("vm_read failed: %s", mach_error_string(kr));
		return 0;
	}

	if(dataPointer == NULL){
		ERR("vm_read didn't work");
		return 0;
	}
	memcpy(dest, dataPointer, size);
	return read;
}

EZAPI remote_write(struct ezinj_ctx *ctx, uintptr_t dest, void *source, size_t size){
	kern_return_t kr;
	vm_size_t pageSz = getpagesize();
	
	void *mem = NULL;
	if(posix_memalign(&mem, pageSz, size) < 0 || mem == NULL){
		PERROR("posix_memalign");
	}
	memcpy(mem, source, size);

	kr = vm_write(
		ctx->task,
		(vm_address_t)dest,
		(vm_offset_t)mem,
		(mach_msg_type_number_t)size
	);
	free(mem);

	if(kr != KERN_SUCCESS){
		ERR("vm_write failed: %s", mach_error_string(kr));
		return 0;
	}
	return size;
}

EZAPI remote_sc_check(struct ezinj_ctx *ctx){
	return 0;
}