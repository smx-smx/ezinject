/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <dlfcn.h>
#include <unistd.h>
#include "ezinject.h"
#include "log.h"
#include "ezinject_util.h"

static EZAPI _resolve_kernel(struct ezinj_ctx *ctx){
	ez_addr kernel = {
		.local = (uintptr_t) get_base(getpid(), "libsystem_kernel", NULL),
		.remote = (uintptr_t) get_base(ctx->target, "libsystem_kernel", NULL)
	};
	DBGPTR(kernel.local);
	DBGPTR(kernel.remote);
	if(!kernel.local || !kernel.remote){
		ERR("Cannot find libsystem_kernel");
		return -1;
	}
	
	void *h_self = dlopen(NULL, RTLD_LAZY);
	if(!h_self){
		ERR("dlopen(NULL) failed: %s", dlerror());
		return -1;
	}

	ez_addr mach_thread_self = sym_addr(h_self, "mach_thread_self", kernel);
	ez_addr thread_terminate = sym_addr(h_self, "thread_terminate", kernel);
	ez_addr mach_port_allocate = sym_addr(h_self, "mach_port_allocate", kernel);
	ez_addr task_self_trap = sym_addr(h_self, "task_self_trap", kernel);

	if(!mach_thread_self.local || !mach_thread_self.remote
	|| !thread_terminate.local || !thread_terminate.remote
	|| !mach_port_allocate.local || !mach_port_allocate.remote
	|| !task_self_trap.local || !task_self_trap.remote
	){
		ERR("Cannot resolve kernel symbols");
		dlclose(h_self);
		return -1;
	}

	ctx->mach_thread_self = mach_thread_self;
	ctx->thread_terminate = thread_terminate;
	ctx->mach_port_allocate = mach_port_allocate;
	ctx->task_self_trap = task_self_trap;

	dlclose(h_self);
	return 0;
}

static EZAPI _resolve_pthread(struct ezinj_ctx *ctx){
	ez_addr pthread = {
		.local = (uintptr_t) get_base(getpid(), "libsystem_pthread", NULL),
		.remote = (uintptr_t) get_base(ctx->target, "libsystem_pthread", NULL)
	};
	DBGPTR(pthread.local);
	DBGPTR(pthread.remote);
	if(!pthread.local || !pthread.remote){
		ERR("Cannot find libsystem_pthread");
		return -1;
	}

	void *h_self = dlopen(NULL, RTLD_LAZY);
	if(!h_self){
		ERR("dlopen(NULL) failed: %s", dlerror());
		return -1;
	}

	ez_addr pthread_create = sym_addr(h_self, "pthread_create", pthread);
	ez_addr pthread_create_from_mach_thread = sym_addr(h_self, "pthread_create_from_mach_thread", pthread);
	ez_addr pthread_join = sym_addr(h_self, "pthread_join", pthread);
	ez_addr pthread_detach = sym_addr(h_self, "pthread_detach", pthread);
	ez_addr pthread_self = sym_addr(h_self, "pthread_self", pthread);

	if(!pthread_create.local || !pthread_create.remote
	|| !pthread_join.local || !pthread_join.remote
	|| !pthread_create_from_mach_thread.local || !pthread_create_from_mach_thread.remote
	|| !pthread_detach.local || !pthread_detach.remote
	|| !pthread_self.local || !pthread_self.remote){
		ERR("Cannot resolve pthread symbols");
		dlclose(h_self);
		return -1;
	}

	ctx->pthread_create = pthread_create;
	ctx->pthread_join = pthread_join;
	ctx->pthread_create_from_mach_thread = pthread_create_from_mach_thread;
	ctx->pthread_detach = pthread_detach;
	ctx->pthread_self = pthread_self;

	dlclose(h_self);
	return 0;
}

EZAPI resolve_libc_symbols(struct ezinj_ctx *ctx){
	void *h_self = dlopen(NULL, RTLD_LAZY);
	if(!h_self){
		ERR("dlopen(NULL) failed: %s", dlerror());
		return -1;
	}

	ez_addr linker = {
		.local  = (uintptr_t) get_base(getpid(), DYN_LINKER_NAME, NULL),
		.remote = (uintptr_t) get_base(ctx->target, DYN_LINKER_NAME, NULL)
	};
	DBGPTR(linker.local);
	DBGPTR(linker.remote);
	if(!linker.local || !linker.remote){
		ERR("Cannot find linker " DYN_LINKER_NAME);
		return -1;
	}

	ez_addr linker_dlopen = sym_addr(h_self, "dlopen", linker);
	ez_addr linker_dlclose = sym_addr(h_self, "dlclose", linker);
	ez_addr linker_dlsym = sym_addr(h_self, "dlsym", linker);
	if(!linker_dlopen.local || !linker_dlclose.local || !linker_dlsym.local){
		ERR("Cannot resolve dl symbols");
		dlclose(h_self);
		return 1;
	}

	// the real libdl is the linker (which holds the implementation of dl* symbols)
	ctx->libdl = linker;
	ctx->libc_dlopen = linker_dlopen;

	ctx->dlopen_offset = PTRDIFF(linker_dlopen.local, linker.local);
	ctx->dlclose_offset = PTRDIFF(linker_dlclose.local, linker.local);
	ctx->dlsym_offset = PTRDIFF(linker_dlsym.local, linker.local);
	dlclose(h_self);

	_resolve_pthread(ctx);
	_resolve_kernel(ctx);
	return 0;
}
