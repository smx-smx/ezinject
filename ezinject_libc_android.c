#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include "ezinject.h"
#include "log.h"
#include "util.h"

// android 10
#include <elf.h>

#define CAST(t, p) (t)(p)

struct gb_linker_ctx {
	int fd;
	size_t memSize;
	void *mem;

	Elf32_Shdr *sec;
	Elf32_Shdr *strtab;
	Elf32_Shdr *symtab;

	ptrdiff_t dlopen_offset;
	ptrdiff_t dlclose_offset;
	ptrdiff_t dlsym_offset;
};

int load_linker(struct gb_linker_ctx *ctx){
	int fd = open(DYN_LINKER_NAME, O_RDONLY);
	if(fd < 0){
		return -1;
	}

	void *pMem = MAP_FAILED;
	struct stat statBuf;

	do {
		if(fstat(fd, &statBuf) < 0){
			return -2;
		}
		pMem = mmap(0, statBuf.st_size, PROT_READ, MAP_SHARED, fd, 0);
	} while(0);

	if(pMem == MAP_FAILED){
		close(fd);
		return -3;
	}

	ctx->fd = fd;
	ctx->memSize = statBuf.st_size;
	ctx->mem = pMem;
	return 0;
}

int linker_find_sections(struct gb_linker_ctx *ctx){
	Elf32_Ehdr *hdr = CAST(Elf32_Ehdr *, ctx->mem);
	Elf32_Shdr *sec = CAST(Elf32_Shdr *, UPTR(hdr) + hdr->e_shoff);

	ctx->sec = sec;

	// get strtab
	Elf32_Shdr *strtab = &sec[hdr->e_shstrndx];
	Elf32_Shdr *symtab = NULL;
	for(int i=0; i<hdr->e_shnum; i++){
		char *name = CAST(char *, UPTR(ctx->mem) + strtab->sh_offset + sec[i].sh_name);

		if(sec[i].sh_type == SHT_DYNSYM && !strcmp(name, ".dynsym")){
			symtab = &sec[i];
			INFO("HAVE SYMTAB");
		}

		if(sec[i].sh_type == SHT_STRTAB && !strcmp(name, ".dynstr")){
			strtab = &sec[i];
			INFO("HAVE STRTAB");
		}
	}

	if(symtab == NULL || strtab == NULL){
		return -1;
	}

	ctx->symtab = symtab;
	ctx->strtab = strtab;
	return 0;
}

int linker_find_symbols(struct gb_linker_ctx *ctx){
	size_t numSyms = ctx->symtab->sh_size / ctx->symtab->sh_entsize;
	DBG("Num syms: %zu", numSyms);

	char *strtab = CAST(char *, UPTR(ctx->mem) + ctx->strtab->sh_offset);
	Elf32_Sym *symtab = CAST(Elf32_Sym *, UPTR(ctx->mem) + ctx->symtab->sh_offset);

	printf("secname: %s\n", CAST(char *, strtab + ctx->symtab->sh_name));

	for(size_t i=0; i<numSyms; i++){
		Elf32_Sym *sym = &symtab[i];
		if(sym->st_name != 0 && sym->st_value != 0 && sym->st_shndx != SHN_UNDEF){
			char *name = strtab + sym->st_name;
			unsigned offset = ctx->sec[sym->st_shndx].sh_offset
				+ (sym->st_value - ctx->sec[sym->st_shndx].sh_addr);
			
			DBG("[%d] %s 0x%x 0x%x\n", i, name, sym->st_value, offset);
			if(!strcmp(name, "__loader_dlopen")){
				ctx->dlopen_offset = offset;
				DBG("__loader_dlopen: %zu", offset);
			} else if(!strcmp(name, "__loader_dlclose")){
				ctx->dlclose_offset = offset;
				DBG("__loader_dlclose: %zu", offset);
			} else if(!strcmp(name, "__loader_dlsym")){
				ctx->dlsym_offset = offset;
				DBG("__loader_dlsym: %zu", offset);
			}
		}
	}
	return 0;
}

int unload_linker(struct gb_linker_ctx *ctx){
	munmap(ctx->mem, ctx->memSize);
	close(ctx->fd);
	return 0;
}

int resolve_libc_symbols_android10(struct ezinj_ctx *ctx){
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

	struct gb_linker_ctx linker_ctx;
	memset(&linker_ctx, 0x00, sizeof(linker_ctx));

	if(load_linker(&linker_ctx) != 0){
		ERR("Failed to open "DYN_LINKER_NAME);
		return -1;
	}

	do {
		if(linker_find_sections(&linker_ctx) != 0){
			ERR("Failed to find linker sections in "DYN_LINKER_NAME);
			break;
		}
		if(linker_find_symbols(&linker_ctx) != 0){
			ERR("Failed to find linker symbols in "DYN_LINKER_NAME);
			break;
		}
	} while(0);

	if(unload_linker(&linker_ctx) != 0){
		ERR("Failed to close "DYN_LINKER_NAME);
		return -1;
	}

	ez_addr dlopen_addr = {
		.local = PTRADD(linker.local, ctx->dlopen_offset),
		.remote = PTRADD(linker.remote, ctx->dlopen_offset)
	};
	DBGPTR(dlopen_addr.local);
	DBGPTR(dlopen_addr.remote);

	// the real libdl is the linker (which holds the implementation of dl* symbols)
	ctx->libdl = linker;
	ctx->libc_dlopen = dlopen_addr;

	ctx->dlopen_offset = linker_ctx.dlopen_offset;
	ctx->dlclose_offset = linker_ctx.dlclose_offset;
	ctx->dlsym_offset = linker_ctx.dlsym_offset;

	DBG("dlopen_offset: 0x%x", ctx->dlopen_offset);
	DBG("dlclose_offset: 0x%x", ctx->dlclose_offset);
	DBG("dlsym_offset: 0x%x", ctx->dlsym_offset);
	return 0;
}

int resolve_libc_symbols(struct ezinj_ctx *ctx){
	INFO("Trying new (Android 10) method");
	if(resolve_libc_symbols_android10(ctx) == 0){
		return 0;
	}
	INFO("Trying previous method");

	/**
	 * libdl.so is a fake library
	 * calling dlsym() on it will give back functions inside the linker
	 **/
	void *libdl = dlopen(DL_LIBRARY_NAME, RTLD_LAZY);
	if(!libdl){
		ERR("dlopen("DL_LIBRARY_NAME") failed: %s", dlerror());
		return 1;
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

	ez_addr linker_dlopen = sym_addr(libdl, "dlopen", linker);
	ez_addr linker_dlclose = sym_addr(libdl, "dlclose", linker);
	ez_addr linker_dlsym = sym_addr(libdl, "dlsym", linker);
	
	DBGPTR(linker_dlopen.local);
	DBGPTR(linker_dlopen.remote);
	
	// the real libdl is the linker (which holds the implementation of dl* symbols)
	ctx->libdl = linker;
	ctx->libc_dlopen = linker_dlopen;

	ctx->dlopen_offset = PTRDIFF(linker_dlopen.local, linker.local);
	ctx->dlclose_offset = PTRDIFF(linker_dlclose.local, linker.local);
	ctx->dlsym_offset = PTRDIFF(linker_dlsym.local, linker.local);

	dlclose(libdl);
	return 0;
}