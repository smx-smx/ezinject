/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <unistd.h>
#include <windows.h>

#include "ezinject.h"
#include "ezinject_util.h"
#include "log.h"

static int chrome_remove_sandbox(struct ezinj_ctx *ctx){
	void *h_ntdll = GetModuleHandleA("ntdll.dll");
	if(!h_ntdll){
		ERR("Failed to locate ntdll.dll");
		return 1;
	}

	ez_addr ntdll = {
		.local = UPTR(h_ntdll),
		.remote = (uintptr_t) get_base(ctx->target, "ntdll.dll", NULL)
	};

	ez_addr nt_map_viewsection = sym_addr(h_ntdll, "NtMapViewOfSection", ntdll);
	ez_addr ldr_load_dll = sym_addr(h_ntdll, "LdrLoadDll", ntdll);

	int written = 0;
#define VALID_ADDR(x) (x.local != 0 && x.remote != 0)
	if(VALID_ADDR(nt_map_viewsection)){
		written = remote_write(ctx, nt_map_viewsection.remote, nt_map_viewsection.local, 64);
		DBG("written: %d", written);
	}
	if(VALID_ADDR(ldr_load_dll)){
		written = remote_write(ctx, ldr_load_dll.remote, ldr_load_dll.local, 64);
		DBG("written: %d", written);
	}
#undef VALID_ADDR
	return 0;
}

int resolve_libc_symbols(struct ezinj_ctx *ctx){
	void *h_kernel32 = GetModuleHandleA("kernel32.dll");
	if(!h_kernel32){
		ERR("Failed to locate kernel32.dll");
		return 1;
	}

#define DBGADDR(x) DBGPTR(x.local); DBGPTR(x.remote)

	ez_addr kernel32 = {
		.local = UPTR(h_kernel32),
		.remote = (uintptr_t) get_base(ctx->target, "kernel32.dll", NULL)
	};
	if(!kernel32.local || !kernel32.remote){
		ERR("Failed to locate kernel32");
		return 1;
	}
	ctx->libdl = kernel32;

	ez_addr virtual_alloc = sym_addr(h_kernel32, "VirtualAlloc", kernel32);
	ez_addr virtual_free = sym_addr(h_kernel32, "VirtualFree", kernel32);
	ez_addr suspend_thread = sym_addr(h_kernel32, "SuspendThread", kernel32);
	ez_addr get_current_thread = sym_addr(h_kernel32, "GetCurrentThread", kernel32);
	ctx->virtual_alloc = virtual_alloc;
	ctx->virtual_free = virtual_free;
	ctx->suspend_thread = suspend_thread;
	ctx->get_current_thread = get_current_thread;

	ez_addr create_file = sym_addr(h_kernel32, "CreateFileA", kernel32);
	ez_addr write_file = sym_addr(h_kernel32, "WriteFile", kernel32);
	ctx->create_file = create_file;
	ctx->write_file = write_file;

	DBGADDR(virtual_alloc);
	DBGADDR(virtual_free);

	void *h_ntdll = GetModuleHandleA("ntdll.dll");
	if(h_ntdll != NULL){
		ez_addr libc_dlopen = sym_addr(h_ntdll, "LdrLoadDll", ctx->libc);

		ez_addr nt_query_proc = sym_addr(h_ntdll, "NtQueryInformationProcess", ctx->libc);
		ez_addr nt_register_dll_noti = sym_addr(h_ntdll, "LdrRegisterDllNotification", ctx->libc);
		ez_addr nt_unregister_dll_noti = sym_addr(h_ntdll, "LdrUnregisterDllNotification", ctx->libc);


		DBGADDR(libc_dlopen);
		DBGADDR(nt_query_proc);
		DBGADDR(nt_register_dll_noti);
		DBGADDR(nt_unregister_dll_noti);



		ctx->nt_query_proc = nt_query_proc;
		ctx->libc_dlopen = libc_dlopen;
		ctx->nt_register_dll_noti = nt_register_dll_noti;
		ctx->nt_unregister_dll_noti = nt_unregister_dll_noti;
	}

	ez_addr alloc_console = sym_addr(h_kernel32, "AllocConsole", kernel32);
	ctx->alloc_console = alloc_console;

	ez_addr load_library = sym_addr(h_kernel32, "LoadLibraryA", kernel32);
	ez_addr free_library = sym_addr(h_kernel32, "FreeLibrary", kernel32);
	ez_addr get_procaddr = sym_addr(h_kernel32, "GetProcAddress", kernel32);

	DBGADDR(alloc_console);
	DBGADDR(load_library);
	DBGADDR(free_library);
	DBGADDR(get_procaddr);

	ctx->dlopen_offset = PTRDIFF(load_library.local, kernel32.local);
	ctx->dlclose_offset = PTRDIFF(free_library.local, kernel32.local);
	ctx->dlsym_offset = PTRDIFF(get_procaddr.local, kernel32.local);

	chrome_remove_sandbox(ctx);

#undef DBGADDR
	return 0;
}
