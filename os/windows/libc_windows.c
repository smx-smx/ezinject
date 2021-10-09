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

int resolve_libc_symbols(struct ezinj_ctx *ctx){
	void *h_ntdll = GetModuleHandleA("ntdll.dll");
	if(!h_ntdll){
		ERR("Failed to locate ntdll.dll");
		return 1;
	}

	void *h_kernel32 = GetModuleHandleA("kernel32.dll");
	if(!h_kernel32){
		ERR("Failed to locate kernel32.dll");
		return 1;
	}

	ez_addr kernel32 = {
		.local = UPTR(h_kernel32),
		.remote = (uintptr_t) get_base(ctx->target, "kernel32.dll", NULL)
	};
	if(!kernel32.local || !kernel32.remote){
		ERR("Failed to locate kernel32");
		return 1;
	}

	ez_addr nt_get_peb = sym_addr(h_ntdll, "RtlGetCurrentPeb", ctx->libc);
	ez_addr nt_query_proc = sym_addr(h_ntdll, "NtQueryInformationProcess", ctx->libc);
	ez_addr nt_write_file = sym_addr(h_ntdll, "NtWriteFile", ctx->libc);
	ez_addr libc_dlopen = sym_addr(h_ntdll, "LdrLoadDll", ctx->libc);
	
	DBGPTR(libc_dlopen.local);
	DBGPTR(libc_dlopen.remote);

	ctx->nt_get_peb = nt_get_peb;
	ctx->nt_query_proc = nt_query_proc;
	ctx->nt_write_file = nt_write_file;
	ctx->libc_dlopen = libc_dlopen;

	ez_addr load_library = sym_addr(h_kernel32, "LoadLibraryA", kernel32);
	ez_addr free_library = sym_addr(h_kernel32, "FreeLibrary", kernel32);
	ez_addr get_procaddr = sym_addr(h_kernel32, "GetProcAddress", kernel32);
	DBGPTR(load_library.local);
	DBGPTR(free_library.local);
	DBGPTR(get_procaddr.local);

	ctx->dlopen_offset = PTRDIFF(load_library.local, kernel32.local);
	ctx->dlclose_offset = PTRDIFF(free_library.local, kernel32.local);
	ctx->dlsym_offset = PTRDIFF(get_procaddr.local, kernel32.local);

	return 0;
}
