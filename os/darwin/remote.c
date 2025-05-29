/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
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

#include "ezinject_util.h"

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
	if(remote_is_remoting(ctx)){
		return -1;
	}

	kern_return_t kr;
	mach_msg_type_number_t count = MACHINE_THREAD_STATE_COUNT;
	kr = thread_set_state(
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

	void *dataPointer = NULL;
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

bool remote_is_remoting(struct ezinj_ctx *ctx){
	return ctx->pthread_create_from_mach_thread.local != 0;
}

EZAPI remote_start_thread(struct ezinj_ctx *ctx, regs_t *regs){
	/**
	 * macOS Sonoma introduced a very questionable change which limits `thread_set_state`
	 * see https://gist.github.com/saagarjha/a70d44951cb72f82efee3317d80ac07f?permalink_comment_id=5075946#gistcomment-5075946
	 *
	 * it's questionable because we can still read/write virtual memory and create remote threads
	 * so this is more annoying than useful
	 */

	 /**
	 * $FIXME: arm64 support (no device to test)
	 * adapted from https://github.com/koekeishiya/yabai/blob/master/src/osax/loader.m
	 */
	thread_state_flavor_t thread_flavor = x86_THREAD_STATE64;
	mach_msg_type_number_t thread_flavor_count = x86_THREAD_STATE64_COUNT;
	kern_return_t kr = thread_create_running(
		ctx->task,
		thread_flavor,
		(thread_state_t)regs,
		thread_flavor_count,
		&ctx->thread
	);
	if (kr != KERN_SUCCESS) {
		ERR("thread_create_running failed: %s", mach_error_string(kr));
		return -1;
	}
	return 0;
}
