/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <elf.h>
#include <link.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "log.h"
#include "ezinject.h"
#include "ezinject_common.h"

#if defined(EZ_TARGET_LINUX)
#define ElfAddr ElfW(Addr)
#define ElfAddr ElfW(Addr)
#define ElfEhdr ElfW(Ehdr)
#define ElfEhdr ElfW(Ehdr)
#define ElfOff ElfW(Off)
#define ElfOff ElfW(Off)
#define ElfPhdr ElfW(Phdr)
#define ElfPhdr ElfW(Phdr)
#define ElfShdr ElfW(Shdr)
#define ElfShdr ElfW(Shdr)
#define ElfSym ElfW(Sym)
#define ElfSym ElfW(Sym)
#elif defined(EZ_TARGET_FREEBSD)
#define ElfAddr Elf_Addr
#define ElfEhdr Elf_Ehdr
#define ElfOff Elf_Off
#define ElfPhdr Elf_Phdr
#define ElfShdr Elf_Shdr
#define ElfSym Elf_Sym
#endif

#define PFLAGS(x)	((((x) & PF_R) ? PROT_READ : 0) | \
			 (((x) & PF_W) ? PROT_WRITE : 0) | \
			 (((x) & PF_X) ? PROT_EXEC : 0))

#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

#define PHDR_MAX 20

struct elfload_ctx {
	int fd;
	uint8_t *data;
	size_t dataSize;

	uintptr_t minva;
	uintptr_t maxva;
	ElfPhdr pt_phdr;
	char *interp;

	ez_addr entry_params;
	ez_addr auxv;
	size_t auxv_size;

	uintptr_t r_elfbase;
	uintptr_t r_phdr;
	uintptr_t r_stack;
	uint8_t *r_stack_data;
	size_t r_stack_size;

	uintptr_t r_maps[PHDR_MAX];
	void *r_backup[PHDR_MAX];
	int phdr_idx;
};

#define R_STACK(ctx, addr) ctx->r_stack + PTRDIFF(addr, ctx->r_stack_data)

// -- util.c: extra API
void *find_map(pid_t pid, int perms, size_t size);
void *get_base_ex(pid_t pid, char *substr, char **ignores, size_t *pSize);
// ----

static ez_region region_sc_code = {
	.start = (void *)&__start_syscall,
	.end = (void *)&__stop_syscall
};

static bool _should_load_phdr(ElfPhdr *phdr){
	switch(phdr->p_type){
		case PT_LOAD:
		/** needed by glibc's ld **/
		case PT_DYNAMIC:
		case PT_GNU_EH_FRAME:
		case PT_GNU_RELRO:
			return true;
		default:
			return false;
	}
}

static EZAPI _remote_load_phdr(
	struct ezinj_ctx *ctx,
	struct elfload_ctx *elf,
	ElfPhdr *phdr,
	uintptr_t *pOutAddr
){
	if(!_should_load_phdr(phdr)){
		return 0;
	}

	if(elf->phdr_idx >= PHDR_MAX){
		ERR("too many program headers");
		return -1;
	}

	size_t pagesz = getpagesize();

	uintptr_t map_start = TRUNCATE(elf->r_elfbase + phdr->p_vaddr, pagesz);
	uintptr_t map_end = (uintptr_t)PAGEALIGN(elf->r_elfbase + phdr->p_vaddr + phdr->p_memsz);
	size_t map_size = (size_t)WORDALIGN(map_end - map_start);

	int p_flags = PFLAGS(phdr->p_flags);

	uintptr_t r_mem = 0;
	for(int i=0; i<PHDR_MAX; i++){
		if(elf->r_maps[i] == map_start){
			r_mem = map_start;
		}
	}
	if(r_mem == 0){
		r_mem = RSCALL6(ctx, __NR_mmap,
			map_start, map_size, p_flags,
			MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
			-1, 0);

		if((intptr_t)r_mem != (intptr_t)MAP_FAILED){
			elf->r_maps[elf->phdr_idx] = r_mem;
		}
	}
	if(r_mem == 0 || (intptr_t)r_mem == (intptr_t)MAP_FAILED){
		ERR("failed to find segment to load segment");
		return -1;
	}

	uintptr_t r_base = elf->r_elfbase + phdr->p_vaddr;

	DBG("base: %p, start: %p, end: %p (size: %lu)",
		elf->r_elfbase, map_start, map_end, map_size);
	DBG("phdr segment: %p", (void *)r_base);

	//uintptr_t r_base = (uintptr_t)find_map(ctx->target, p_flags, map_size);

#if 0
	uint8_t *backup = calloc(1, map_size);
	if(remote_read(ctx, backup, r_base, map_size) != (intptr_t)map_size){
		ERR("failed to backup remote segment");
		return -1;
	}
	elf->r_backup[elf->phdr_idx++] = backup;
#endif

	DBG("writing phdr @0x%lx -> %p",
		phdr->p_offset, (void *)r_base
	);
	
	size_t fileSize = (size_t)WORDALIGN(phdr->p_filesz);
	if(remote_write(ctx, r_base,
		&elf->data[phdr->p_offset],
		fileSize) != (intptr_t)fileSize
	){
		ERR("failed to copy segment data");
		return -1;
	}

	*pOutAddr = r_base;
	return 0;
}

static EZAPI _remote_get_argv0(struct ezinj_ctx *ctx, char **pResult){
	char path[64];
	snprintf(path, sizeof(path), "/proc/%u/cmdline", ctx->target);
	FILE *cmdline = fopen(path, "rb");
	if(!cmdline){
		return -1;
	}

	int ch = -1; int len = 0;
	for(len=0; ch != 0; len++){
		ch = fgetc(cmdline);
	}
	int argv0_sz = len + 1;
	char *argv0 = malloc(argv0_sz);
	rewind(cmdline);
	fread(argv0, 1, argv0_sz, cmdline);
	fclose(cmdline);

	*pResult = argv0;
	return 0;
}

static EZAPI _remote_read_stack(
	struct ezinj_ctx *ctx,
	struct elfload_ctx *elf,
	uint8_t **pOutMem, size_t *pOutSize
){
	size_t stack_size = 0;
	uintptr_t stack_base = (uintptr_t)get_base_ex(ctx->target, "[stack]", NULL, &stack_size);
	if(stack_base == 0){
		ERR("get_base_ex: [stack] region not found");
		return -1;
	}
	elf->r_stack = stack_base;

	stack_size = (size_t)WORDALIGN(stack_size);
	uint8_t *mem = calloc(1, stack_size);

	if(remote_read(ctx, mem, stack_base, stack_size) != (intptr_t)stack_size){
		free(mem);
		ERR("remote_read: failed to read remote stack");
		return -1;
	}

	*pOutMem = mem;
	*pOutSize = stack_size;
	return 0;
}

static EZAPI _remote_find_auxv(
	struct ezinj_ctx *ctx,
	struct elfload_ctx *elf,
	ez_addr *pOutArgv,
	ez_addr *pOutAuxv
){
	char *argv0 = NULL;
	if(_remote_get_argv0(ctx, &argv0) != 0){
		ERR("remote_get_argv0 failed");
		return -1;
	}
	size_t argv0_sz = strlen(argv0) + 1;

	intptr_t rc = -1;
	uint8_t *pStack = NULL;
	size_t stack_size;
	do {
		if(_remote_read_stack(ctx, elf, &pStack, &stack_size) != 0){
			ERR("remote_read_stack failed");
			break;
		}
		elf->r_stack_data = pStack;
		elf->r_stack_size = stack_size;

		int occurrences = 0;

		// find where argv0 is in the stack
		uint8_t *stack_top = pStack + stack_size;
		uint8_t *p = stack_top - argv0_sz;
		ssize_t remaining = (ssize_t)(stack_size - argv0_sz);
		for(; remaining > 0; remaining--, p--){
			if(!strncmp((char *)p, argv0, argv0_sz)){
				if(occurrences++ > 0){
					// skip "_" environment var
					if(*(p - 1) != '=') break;
				}
			}
		}
		int found = 0;

		found = remaining != 0;
  		if(!found) break;

		void *l_argv0_addr = p;
		uintptr_t r_argv0_addr = R_STACK(elf, p);
		DBG("argv0: %p", (void *)r_argv0_addr);

		uintptr_t *pwords = (uintptr_t *)WORDALIGN(p);
		for(; remaining > 0; remaining-=sizeof(uintptr_t), pwords--){
			if(*pwords == r_argv0_addr){
				break;
			}
		}
		p = (uint8_t *)pwords;

		found = remaining != 0;
		if(!found) break;

		void *argv0_ptr = p;
		uintptr_t r_argv0_ptr = R_STACK(elf, p);

		DBG("argv0_ptr: %p", argv0_ptr);

		// good, now find auxv
		// step 1: skip all argv
		char **strp = (char **)argv0_ptr;
		while(*(strp++) != NULL);

		// step 2: skip all envp
		while(*(strp++) != NULL);

		DBG("auxv_ptr: %p", strp);

		ez_addr argv_addr = {
			.local = argv0_ptr,
			.remote = r_argv0_ptr
		};
		ez_addr auxv_addr = {
			.local = (uintptr_t)strp,
			.remote = elf->r_stack + PTRDIFF(strp, pStack)
		};

		*pOutArgv = argv_addr;
		*pOutAuxv = auxv_addr;

		rc = 0;
	} while(0);
	free(argv0);
	return rc;
}

static EZAPI _remote_prepare_elf(
	struct ezinj_ctx *ctx,
	struct elfload_ctx *elf,
	struct elfload_ctx *elf_interp
){
	ez_addr argv0;
	ez_addr auxv;
	if(_remote_find_auxv(ctx, elf, &argv0, &auxv) != 0){
		ERR("remote_find_auxv failed");
		return -1;
	}

	/**
	 * this is the list of parameters initially passed in by the kernel
	 * http://articles.manugarg.com/aboutelfauxiliaryvectors
	 * 
	 * argc -> argv -> envp -> auxv
	 */
	ez_addr argc = {
		.local = argv0.local - sizeof(long int),
		.remote = argv0.remote - sizeof(long int)
	};
	elf->entry_params = argc;

	DBGPTR(auxv.remote);

	ElfEhdr *ehdr = (ElfEhdr *)elf->data;

	ElfW(auxv_t) *av = (ElfW(auxv_t) *)auxv.local;
	for(;av->a_type != AT_NULL; av++){
		printf("%d is 0x%x\n", av->a_type, av->a_un.a_val);

		switch(av->a_type){
			case AT_PHDR:
				DBG("AT_PHDR: %p", (void *)(elf->r_elfbase + ehdr->e_phoff));
				av->a_un.a_val = (void *)(elf->r_elfbase + ehdr->e_phoff);
				break;
			case AT_PHNUM:
				DBG("AT_PHNUM: %p", ehdr->e_phnum);
				av->a_un.a_val = ehdr->e_phnum;
				break;
			case AT_PHENT:
				DBG("AT_PHENT: %p", ehdr->e_phentsize);
				av->a_un.a_val = ehdr->e_phentsize;
				break;
			case AT_ENTRY:
				DBG("AT_ENTRY: %p", elf->r_elfbase + ehdr->e_entry);
				av->a_un.a_val = elf->r_elfbase + ehdr->e_entry;
				break;
			case AT_EXECFN:
				// no need to patch this, keep original argv[0]
				break;
			case AT_BASE:
				DBG("AT_BASE: %p", elf_interp->r_elfbase);
				av->a_un.a_val = elf_interp->r_elfbase;
				break;
		}
	}

	size_t auxv_size = WORDALIGN(PTRDIFF(av, auxv.local));
	elf->auxv_size = auxv_size;
	return 0;
}

static EZAPI _elf_get_bounds(
	struct elfload_ctx *elf,
	ElfAddr *pOutMinVa,
	ElfAddr *pOutMaxVa
){
	ElfAddr min_va = (ElfAddr) -1;
	ElfAddr max_va = 0;

	ElfEhdr *ehdr = (ElfEhdr *)elf->data;
	ElfPhdr *phdrs = (ElfPhdr *)&elf->data[ehdr->e_phoff];
	for(int i=0; i<ehdr->e_phnum; i++){
		ElfPhdr *cur_phdr = &phdrs[i];
		
		if(!_should_load_phdr(cur_phdr)){
			continue;
		}

		ElfAddr left = cur_phdr->p_vaddr;
		ElfAddr right = cur_phdr->p_vaddr + cur_phdr->p_memsz;
		DBG("phdr left: %lu, right: %lu", left, right);

		if(left < min_va){
			min_va = left;
		}
		if(right > max_va){
			max_va = right;
		}
	}

	size_t pagesz = getpagesize();

	if(min_va != -1 && min_va < max_va){
		*pOutMinVa = TRUNCATE(min_va, pagesz);
		*pOutMaxVa = ALIGN(max_va, pagesz);
		return 0;
	}
	return -1;
}

static EZAPI _remote_load_elf(
	struct ezinj_ctx *ctx,
	struct elfload_ctx *elf,
	const char *elf_path,
	bool is_interp
){

	int fd = open(elf_path, O_RDONLY);
	if(fd < 0){
		ERR("failed to open %s", elf_path);
		PERROR("open");
		return -1;
	}
	elf->fd = fd;

	struct stat statBuf;
	uint8_t *pMem = NULL;
	ElfEhdr *ehdr = NULL;

	intptr_t rc = -1;
	do {
		if(fstat(fd, &statBuf) < 0){
			PERROR("fstat");
			break;
		}

		pMem = (uint8_t *)mmap(0, statBuf.st_size,
			PROT_READ, MAP_SHARED, fd, 0);
		
		if(pMem == NULL || pMem == MAP_FAILED){
			PERROR("mmap");
			break;
		}
		elf->data = pMem;
		elf->dataSize = statBuf.st_size;
		DBGPTR(elf->data);

		ehdr = (ElfEhdr *)pMem;
		if(ehdr->e_ident[EI_MAG0] != ELFMAG0
		|| ehdr->e_ident[EI_MAG1] != ELFMAG1
		|| ehdr->e_ident[EI_MAG2] != ELFMAG2
		|| ehdr->e_ident[EI_MAG3] != ELFMAG3
		|| (ehdr->e_ident[EI_CLASS] != ELFCLASS32 && ehdr->e_ident[EI_CLASS] != ELFCLASS64)
		|| ehdr->e_ident[EI_VERSION] != EV_CURRENT
		// must be a DYN elf
		|| ehdr->e_type != ET_DYN
		){
			ERR("Invalid or unsupported ELF file");
			break;
		}

		ElfAddr min_va;
		ElfAddr max_va;

		if(_elf_get_bounds(elf, &min_va, &max_va) != 0){
			ERR("invalid ELF bounds");
			break;
		}
		DBG("left: %lu, right: %lu", min_va, max_va);


		intptr_t r_base = (intptr_t)RSCALL6(ctx, __NR_mmap,
			0,
			max_va - min_va, PROT_NONE,
			MAP_PRIVATE | MAP_ANONYMOUS,
			-1, 0
		);
		if(r_base == 0 || r_base == -1){
			ERR("remote mmap failed");
			break;
		}
		DBG("elf base: %p", r_base);

		RSCALL2(ctx, __NR_munmap, r_base, max_va - min_va);
		elf->r_elfbase = r_base;

		ElfPhdr *phdrs = (ElfPhdr *)&pMem[ehdr->e_phoff];
		
		ElfPhdr *pt_phdr = NULL;
		ElfPhdr *pt_interp = NULL;

		for(int i=0; i<ehdr->e_phnum; i++){
			ElfPhdr *cur_phdr = &phdrs[i];
			
			uintptr_t r_addr = 0;
			if(_remote_load_phdr(ctx, elf, cur_phdr, &r_addr) != 0){
				ERR("failed to load phdr %i", i);
				break;
			}
			elf->phdr_idx++;

			if(pt_interp == NULL && cur_phdr->p_type == PT_INTERP){
				pt_interp = cur_phdr;
			}

			if(pt_phdr == NULL && cur_phdr->p_type == PT_PHDR){
				pt_phdr = cur_phdr;
				elf->pt_phdr = *cur_phdr;
				elf->r_phdr = r_addr;
			}
		}

		if(!is_interp){
			if(pt_phdr == NULL){
				ERR("PT_PHDR not found");
				break;
			}
			if(pt_interp == NULL){
				ERR("PT_INTERP not found");
				break;
			}

			char *interp = calloc(1, pt_interp->p_filesz);
			strncpy(interp,
				&elf->data[pt_interp->p_offset],
				pt_interp->p_filesz
			);
			if(interp[pt_interp->p_filesz - 1] != '\0'){
				ERR("invalid PT_INTERP");
				break;
			}
			DBG("interp: %s", interp);
			elf->interp = interp;
		}

		rc = 0;
	} while(0);
	return rc;
}

EZAPI remote_libc_load(struct ezinj_ctx *ctx){
	struct elfload_ctx elf;
	memset(&elf, 0x00, sizeof(elf));

	struct elfload_ctx elf_interp;
	memset(&elf_interp, 0x00, sizeof(elf_interp));


	puts("=====================");
	// step 1: load the ELF file in-place inside the remote process
	if(_remote_load_elf(ctx, &elf, "ezinject_libcloader_helper", false) != 0){
		ERR("remote_load_elf failed");
		return -1;
	}

	if(elf.interp == NULL){
		ERR("Missing PT_INTERP");
		return -1;
	}

	puts("=====================");
	// step 2: load interp
	if(_remote_load_elf(ctx, &elf_interp, elf.interp, true) != 0){
		ERR("remote_load_elf: failed to load interp");
		return -1;
	}

	// patch auxv
	if(_remote_prepare_elf(ctx, &elf, &elf_interp) != 0){
		ERR("remote_prepare_elf failed");
		return -1;
	}

	uintptr_t interp_entry = elf_interp.r_elfbase + ((ElfEhdr *)elf_interp.data)->e_entry;
	DBGPTR(elf_interp.r_elfbase);
	DBGPTR(((ElfEhdr *)elf_interp.data)->e_entry);

	// assume entry is beginning of .text
	DBG("add-symbol-file %s %p", elf.interp, interp_entry);
	FILE *cmd = fopen(".target_gdbinit", "w");
	fprintf(cmd, "add-symbol-file %s %p", elf.interp, interp_entry);
	fclose(cmd);

	// create alt stack for interp
	uintptr_t r_altstack = RSCALL6(ctx, __NR_mmap,
		0,
		elf.r_stack_size,
		PROT_READ | PROT_WRITE,
		MAP_ANONYMOUS | MAP_PRIVATE, -1, 0
	);
	if(r_altstack == 0 || (intptr_t)r_altstack == -1){
		ERR("failed to allocate temp-stack");
		return -1;
	}

	uintptr_t r_altstack_top = r_altstack + elf.r_stack_size;

	// important: keep original program stack for this rcall
	// but pass the alt stack to interp (it will pivot to it)
	ctx->syscall_mode = -1;
	ctx->branch_target.remote = interp_entry;

	off_t params_off = PTRDIFF(elf.entry_params.local, elf.r_stack_data);
	uintptr_t altstack_params = r_altstack + params_off;

	DBG("interp entry: %p", interp_entry);
	DBG("altstack: %p - %p", (void *)r_altstack, (void *)r_altstack_top);
	DBG("params: %p", altstack_params);

	// write patched AUXV to altstack
	size_t params_size = WORDALIGN(elf.r_stack_size - params_off);
	if(remote_write(ctx,
		altstack_params,
		elf.entry_params.local,
		params_size
	) != (intptr_t)params_size){
		ERR("failed to write params");
		return -1;
	}

	// run interp, passing in altstack
	RSCALL0(ctx, altstack_params);
	ctx->syscall_mode = 1;
	return 0;
}
