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

#define CAST(t, p) (t)(p)

struct gb_linker_ctx {
	int fd;
	size_t memSize;
	void *mem;

	Elf32_Shdr *strtab;
	Elf32_Shdr *data;
	Elf32_Shdr *rodata;
	Elf32_Shdr *text;

	off_t dlopen_offset;
	off_t dlclose_offset;
	off_t dlsym_offset;
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

	// get strtab
	Elf32_Shdr *strtab = &sec[hdr->e_shstrndx];
	ctx->strtab = strtab;
	if(strtab == NULL){
		return -1;
	}

	Elf32_Shdr *data = NULL;
	Elf32_Shdr *rodata = NULL;
	Elf32_Shdr *text = NULL;
	for(int i=0; i<hdr->e_shnum && (rodata == NULL || data == NULL || text == NULL); i++){
		char *name = CAST(char *, UPTR(ctx->mem) + strtab->sh_offset + sec[i].sh_name);
		if(rodata == NULL && !strcmp(name, ".rodata")){
			rodata = &sec[i];
		} else if(data == NULL && !strcmp(name, ".data")){
			data = &sec[i];
		} else if(text == NULL && !strcmp(name, ".text")){
			text = &sec[i];
		}
	}
	ctx->rodata = rodata;
	if(rodata == NULL){
		return -2;
	}

	ctx->data = data;
	if(data == NULL){
		return -3;
	}

	ctx->text = text;
	if(text == NULL){
		return -4;
	}

	return 0;
}

int find_libdl_symtab(struct gb_linker_ctx *ctx, Elf32_Sym **pSymtab, int *pNumSyms){
	void *rodata_start = CAST(void *, UPTR(ctx->mem) + ctx->rodata->sh_offset);
	void *data_start   = CAST(void *, UPTR(ctx->mem) + ctx->data->sh_offset);
	
	#define DATA_PHYS(p) (UPTR(p) - ctx->data->sh_addr + UPTR(data_start))
	#define DATA_VIRT(p) (UPTR(p) - UPTR(data_start) + ctx->data->sh_addr)

	#define RODATA_VIRT(p) (UPTR(p) - UPTR(rodata_start) + ctx->rodata->sh_addr)

	char libdl_strtab_begin[] = "dlopen\0dlclose\0dlsym\0dlerror\0dladdr";
	void *match = NULL;

	// find the .rodata address to the strtab string
	match = memmem(rodata_start, ctx->rodata->sh_size, libdl_strtab_begin, sizeof(libdl_strtab_begin));
	if(match == NULL){
		return -1;
	}

	uintptr_t strtab_string_addr = RODATA_VIRT(match);
	DBG("strtab string: %zu", strtab_string_addr);
	
	// now find the respective .data pointer
	match = memmem(data_start, ctx->data->sh_size, &strtab_string_addr, sizeof(strtab_string_addr));
	if(match == NULL){
		return -2;
	}

	uintptr_t strtab_string_xref = DATA_VIRT(match);
	DBG("strtab ptr: %zu", strtab_string_xref);

	/**
	struct soinfo {
		...
		const char *strtab; // <-- found this
		Elf32_Sym *symtab;
		unsigned nbucket;
		unsigned nchain;
		...
	}
	**/

	off_t offset = 0;
	offset += sizeof(const char *);

	// we now found the "const char *strtab" member of "struct soinfo"
	// get the next item, "Elf32_Sym *symtab;"
	uint32_t libdl_symtab_xref = *CAST(uint32_t *,
		DATA_PHYS(UPTR(strtab_string_xref) + offset)
	);
	offset += sizeof(Elf32_Sym *);
	DBG("symtab ptr: 0x%x", libdl_symtab_xref);

	unsigned nbucket = *CAST(unsigned *,
		DATA_PHYS(UPTR(strtab_string_xref) + offset)
	);
	offset += sizeof(unsigned);

	unsigned nchain = *CAST(unsigned *,
		DATA_PHYS(UPTR(strtab_string_xref) + offset)
	);
	offset += sizeof(unsigned);

	if(nbucket != 1){
		return -3;
	}
	DBG("nchain: %u", nchain);

	Elf32_Sym *libdl_symtab = CAST(Elf32_Sym *,
		DATA_PHYS(libdl_symtab_xref)
	);

	*pSymtab = libdl_symtab;
	*pNumSyms = nchain;
	return 0;
}

int unload_linker(struct gb_linker_ctx *ctx){
	munmap(ctx->mem, ctx->memSize);
	close(ctx->fd);
	return 0;
}

int find_libdl_symbols(struct gb_linker_ctx *ctx, Elf32_Sym *libdl_symtab, int nchain){
	void *text_start   = CAST(void *, UPTR(ctx->mem) + ctx->text->sh_offset);
	#define TEXT_PHYS(p) (UPTR(p) - ctx->text->sh_addr + UPTR(text_start))
	
	Elf32_Sym *dlopen_sym = NULL;
	Elf32_Sym *dlclose_sym = NULL;
	Elf32_Sym *dlsym_sym = NULL;

	const unsigned dlopen_str_offset = 0;
	const unsigned dlclose_str_offset = dlopen_str_offset + sizeof("dlopen");
	const unsigned dlsym_str_offset = dlclose_str_offset + sizeof("dlclose");

	for(int i=0; i<nchain && (dlopen_sym == NULL || dlclose_sym == NULL || dlsym_sym == NULL); i++){
		Elf32_Sym *sym = &libdl_symtab[i];

		if(sym->st_info == STB_GLOBAL << 4
	    && sym->st_shndx == 1
		){
			if(dlopen_sym == NULL && sym->st_name == dlopen_str_offset){
				dlopen_sym = sym;
			} else if(dlclose_sym == NULL && sym->st_name == dlclose_str_offset){
				dlclose_sym = sym;
			} else if(dlsym_sym == NULL && sym->st_name == dlsym_str_offset){
				dlsym_sym = sym;
			}
		}
	}
	if(dlopen_sym == NULL || dlclose_sym == NULL || dlsym_sym == NULL){
		return -1;
	}

	uint32_t dlopen_addr = dlopen_sym->st_value;
	uint32_t dlclose_addr = dlclose_sym->st_value;
	uint32_t dlsym_addr = dlsym_sym->st_value;
	DBG("dlopen addr: 0x%x", dlopen_addr);
	DBG("dlclose addr: 0x%x", dlclose_addr);
	DBG("dlsym addr: 0x%x", dlsym_addr);

	ctx->dlopen_offset = TEXT_PHYS(dlopen_addr) - UPTR(ctx->mem);
	ctx->dlclose_offset = TEXT_PHYS(dlclose_addr) - UPTR(ctx->mem);
	ctx->dlsym_offset = TEXT_PHYS(dlsym_addr) - UPTR(ctx->mem);
	DBG("dlopen offset: 0x"LX, ctx->dlopen_offset);
	DBG("dlclose offset: 0x"LX, ctx->dlclose_offset);
	DBG("dlsym offset: 0x"LX, ctx->dlsym_offset);
	return 0;
}

int resolve_libc_symbols(struct ezinj_ctx *ctx){
	struct gb_linker_ctx linker;
	memset(&linker, 0x00, sizeof(linker));

	int rc = 1;

	if(load_linker(&linker) != 0){
		return rc;
	}

	do {
		if(linker_find_sections(&linker) != 0){
			break;
		}

		Elf32_Sym *libdl_symtab = NULL;
		int numSyms;
		if(find_libdl_symtab(&linker, &libdl_symtab, &numSyms) != 0){
			break;
		}

		if(find_libdl_symbols(&linker, libdl_symtab, numSyms) != 0){
			break;
		}
		rc = 0;
	} while(0);

	unload_linker(&linker);

	ctx->dlopen_offset = linker.dlopen_offset;
	ctx->dlclose_offset = linker.dlclose_offset;
	ctx->dlsym_offset = linker.dlsym_offset;

	ez_addr linker_addr = {
		.local  = (uintptr_t) get_base(getpid(), DYN_LINKER_NAME, NULL),
		.remote = (uintptr_t) get_base(ctx->target, DYN_LINKER_NAME, NULL)
	};
	if(linker_addr.local == 0){
		ERR("Failed to locate " DYN_LINKER_NAME);
		return 1;
	}
	DBGPTR(linker_addr.local);
	DBGPTR(linker_addr.remote);

	ez_addr linker_dlopen = {
		.local = PTRADD(linker_addr.local, linker.dlopen_offset),
		.remote = PTRADD(linker_addr.remote, linker.dlopen_offset)
	};

	ctx->libc_dlopen = linker_dlopen;

	ctx->libdl = linker_addr;
	return rc;
}