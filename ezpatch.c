#define _GNU_SOURCE
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

#include "util.h"

#define CHECK(x) ({\
long _tmp = (x);\
printf("%s = %lu\n", #x, _tmp);\
if(_tmp==-1)perror("ptrace");\
_tmp;})

void apply_patch(pid_t target, void *target_addr, void *patch, size_t patchlen)
{
	void **target_addr_p = (void**)target_addr;
	void **patch_p = (void**)patch;
	while(patchlen >= sizeof(void*))
	{
		ptrace(PTRACE_POKETEXT, target, target_addr_p++, *(patch_p++));
		patchlen -= sizeof(void*);
	}
	void *last = (void*)ptrace(PTRACE_PEEKTEXT, target, target_addr_p, 0);
	memcpy((char*)&last, patch_p, patchlen);
	ptrace(PTRACE_POKETEXT, target, target_addr_p, last);
}

int main(int argc, char *argv[])
{
	if(argc < 3)
	{
		puts("You're using it wrong.\nUsage: %s pid FunctionName=patchfile [FunctionName2=patchfile2 ...]");
		return 1;
	}
	pid_t target = atoi(argv[1]);
	char path[128];
	readlink("/proc/self/exe", path, 128);
	char *dir = dirname(path);
	chdir(dir);
	chdir("patches");
	snprintf(path, 128, "/proc/%u/exe", target);
	puts(path);
	void *hndl = dlopen(path, RTLD_LAZY);
	printf("dlopen()=%p\n", hndl);
	puts(dlerror());
	struct link_map *lmap;
	int ret = dlinfo(hndl, RTLD_DI_LINKMAP, &lmap);
	printf("dlinfo() = %u, lmap=%p\n", ret, lmap);

	char *sym_base = 0; //(char *)lmap->l_addr;
	printf("sym_base=%p\n", sym_base);

	CHECK(ptrace(PTRACE_ATTACH, target, 0, 0));

	char *target_base = get_base(target, 0);
	char *target_libc_base = get_base(target, "libc");
	printf("Target base: %p\nTarget libc base: %p\n", target_base, target_libc_base);

	for(int i = 2; i < argc; ++i)
	{
		char *eqpos;
		if((eqpos = strchr(argv[i], '=')) == 0) continue;
		char *cmd = strdup(argv[i]);
		char *filename = eqpos - argv[i] + cmd;
		*(filename++) = 0;
		char *funcname = cmd;

//		char *funcadr = dlsym(hndl, funcname);
		char *funcadr = (char*)0x00022b10; 
		if(!funcadr)
		{
			printf("Function %s not found!\n", funcname);
			goto out;
		}
		
//		funcadr = funcadr - sym_base + target_base;

		FILE *patchfile = fopen(filename, "r");
		if(!patchfile)
		{
			printf("Failed to open patch file %s: %s\n", filename, strerror(errno));
			goto out;
		}

		fseek(patchfile, 0, SEEK_END);
		int patchsz = ftell(patchfile);
		fseek(patchfile, 0, SEEK_SET);
		char *patchdata = malloc(patchsz);
		fread(patchdata, 1, patchsz, patchfile);
		fclose(patchfile);
		
		printf("Applying patch: %s -> %s\n", funcname, filename);
		printf("%u bytes at at %p\n", patchsz, funcadr);
		apply_patch(target, funcadr, patchdata, patchsz);

		free(patchdata);

out:
		free(cmd);
	}

//	dlclose(hndl);

	CHECK(ptrace(PTRACE_DETACH, target, 0, 0));

	return 0;
}
