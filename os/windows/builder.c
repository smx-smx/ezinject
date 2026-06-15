/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "ezinject_util.h"
#include "ezinject.h"
#include "os/builder.h"
#include "log.h"
#include "os/windows/util.h"

void os_pagesize_init(struct ezinj_ctx *ctx){
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	ctx->pagesize = sysInfo.dwPageSize;
}

int os_post_attach_wait(struct ezinj_ctx *ctx){
	UNUSED(ctx);
	return 0;
}

bool os_forward_signal(struct ezinj_ctx *ctx, int status, bool syscall_mode){
	UNUSED(ctx);
	UNUSED(status);
	UNUSED(syscall_mode);
	return false;
}

void os_invoke_begin(struct ezinj_ctx *ctx, struct injcode_call *rcall){
	ctx->platform.r_ezstate_addr = RCALL_FIELD_ADDR(rcall, ezstate);
}

uintptr_t os_alloc_retry(struct ezinj_ctx *ctx, uintptr_t result, size_t mapping_size){
	UNUSED(ctx);
	UNUSED(mapping_size);
	return result;
}

int os_pl_copy(struct ezinj_ctx *ctx, size_t mapping_size){
	struct injcode_bearing *br = (struct injcode_bearing *)ctx->mapped_mem.local;
	if(remote_write(ctx,
		ctx->mapped_mem.remote,
		(void *)ctx->mapped_mem.local,
		br->mapping_size
	) != br->mapping_size){
		PERROR("remote_write failed");
		return -1;
	}
	return 0;
}

bool os_should_retry(struct ezinj_ctx *ctx, int err){
	UNUSED(ctx);
	UNUSED(err);
	return false;
}

extern int push_string(struct ezinj_strings *strings, enum ezinj_str_id str_id, const char *str);

#define PUSH_STRING(id, str) do { \
	if(push_string(strings, id, str) < 0) return; \
} while(0)

void os_strings_init(struct ezinj_ctx *ctx, struct ezinj_strings *strings, struct os_builder_ctx *os_ctx){
	UNUSED(ctx);
	memset(os_ctx, 0, sizeof(*os_ctx));

	PUSH_STRING(EZSTR_API_CREATE_EVENT, "CreateEventA");
	PUSH_STRING(EZSTR_API_CREATE_THREAD, "CreateThread");
	PUSH_STRING(EZSTR_API_CLOSE_HANDLE, "CloseHandle");
	PUSH_STRING(EZSTR_API_WAIT_FOR_SINGLE_OBJECT, "WaitForSingleObject");
	PUSH_STRING(EZSTR_API_GET_EXIT_CODE_THREAD, "GetExitCodeThread");
}

void os_bearing_setup(struct injcode_bearing *br, struct ezinj_ctx *ctx, struct os_builder_ctx *os_ctx){
	UNUSED(os_ctx);
	br->platform.CreateFileA = (void *)ctx->platform.create_file.remote;
	br->platform.WriteFile = (void *)ctx->platform.write_file.remote;
	br->platform.CloseHandle = (void *)ctx->platform.close_handle.remote;
	br->platform.LdrRegisterDllNotification = (void *)ctx->platform.nt_register_dll_noti.remote;
	br->platform.LdrUnregisterDllNotification = (void *)ctx->platform.nt_unregister_dll_noti.remote;
	br->platform.kernel32_base = ctx->libdl.remote;
}

void os_rcall_setup(struct ezinj_ctx *ctx, struct injcode_call *rcall, uintptr_t r_call_args){
	UNUSED(r_call_args);
	rcall->platform.VirtualAlloc = (void *)ctx->platform.virtual_alloc.remote;
	rcall->platform.VirtualFree = (void *)ctx->platform.virtual_free.remote;
	rcall->platform.SuspendThread = (void *)ctx->platform.suspend_thread.remote;
	rcall->platform.GetCurrentThread = (void *)ctx->platform.get_current_thread.remote;
}

void os_plt_resolve(void){}
void os_print_maps(void){}
