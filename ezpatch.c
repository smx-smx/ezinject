/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <link.h>
#include <libgen.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>

#include "ezinject_util.h"
#include "elfparse.h"

LOG_SETUP(V_DBG);

void apply_patch(pid_t target, void *target_addr, void *patch, size_t patchlen)
{
	void **target_addr_p = (void**)target_addr;
	void **patch_p = (void**)patch;
	while(patchlen >= sizeof(void*))
	{
		ptrace(PTRACE_POKETEXT, target, target_addr_p++, *(patch_p++));
		patchlen -= sizeof(void*);
	}
	if(!patchlen) return;
	void *last = (void*)ptrace(PTRACE_PEEKTEXT, target, target_addr_p, 0);
	memcpy((char*)&last, patch_p, patchlen);
	ptrace(PTRACE_POKETEXT, target, target_addr_p, last);
}

int main(int argc, char *argv[])
{
	if(argc < 3)
	{
		ERR("You're using it wrong.");
		ERR("Usage: %s pid FunctionName=patchfile [FunctionName2=patchfile2 ...]", argv[0]);
		return 1;
	}
	pid_t target = atoi(argv[1]);
	char path[128];
	readlink("/proc/self/exe", path, 128);
	char *dir = dirname(path);
	chdir(dir);
	chdir("patches");
	snprintf(path, 128, "/proc/%u/exe", target);

	void *hndl = elfparse_createhandle(path);
	bool needs_reloc = elfparse_needs_reloc(hndl);

	CHECK(ptrace(PTRACE_ATTACH, target, 0, 0));

	char *target_base = get_base(target, 0, NULL);
	char *target_libc_base = get_base(target, "libc-", NULL);
	DBG("Target base: %p", target_base);
	DBG("Target libc base: %p", target_libc_base);

	for(int i = 2; i < argc; ++i)
	{
		char *eqpos;
		if((eqpos = strchr(argv[i], '=')) == 0) continue;
		char *cmd = strdup(argv[i]);
		char *filename = eqpos - argv[i] + cmd;
		*(filename++) = 0;
		char *funcname = cmd;

		char *funcadr = (char *)elfparse_getfuncaddr(hndl, funcname);
		if(!funcadr)
		{
			WARN("Function %s not found!", funcname);
			goto out;
		}
		if(needs_reloc)
			funcadr += (uintptr_t)target_base;

		FILE *patchfile = fopen(filename, "r");
		if(!patchfile)
		{
			WARN("Failed to open patch file %s: %s", filename, strerror(errno));
			goto out;
		}

		fseek(patchfile, 0, SEEK_END);
		int patchsz = ftell(patchfile);
		fseek(patchfile, 0, SEEK_SET);
		char *patchdata = malloc(patchsz);
		fread(patchdata, 1, patchsz, patchfile);
		fclose(patchfile);
		
		INFO("Applying patch: %s -> %s", funcname, filename);
		DBG("%u bytes at at %p", patchsz, funcadr);
		apply_patch(target, funcadr, patchdata, patchsz);

		free(patchdata);

out:
		free(cmd);
	}

	elfparse_destroyhandle(hndl);

	CHECK(ptrace(PTRACE_DETACH, target, 0, 0));

	return 0;
}
