#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>
#include <link.h>

#include "config.h"
#include "ezinject_util.h"

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
struct elfparse_info
{
	char *path;
	int fd;
	void *mapping;
	size_t len;

	ElfEhdr *ehdr;
	ElfShdr *sec;

	char *strtab;
	ElfSym *symtab;
	int symtab_entries;

	char *dynstr;
	ElfSym *dynsym;
	int dynsym_entries;
};

static void elfparse_parse(struct elfparse_info *hndl);

void *elfparse_createhandle(const char *procpath) {
	struct elfparse_info *hndl = NULL;
	int rc = -1;
	do {
		hndl = calloc(1, sizeof(struct elfparse_info));
		if(hndl == NULL){
			break;
		}
		hndl->path = strdup(procpath);
		if(hndl->path == NULL){
			break;
		}
		hndl->fd = open(hndl->path, O_RDONLY);
		if(hndl->fd < 0){
			break;
		}

		struct stat statBuf;
		if(fstat(hndl->fd, &statBuf) < 0){
			break;
		}

		hndl->len = statBuf.st_size;
		hndl->mapping = mmap(0, hndl->len, PROT_READ, MAP_SHARED, hndl->fd, 0);
		if(hndl->mapping == MAP_FAILED){
			break;
		}

		elfparse_parse(hndl);
		rc = 0;
	} while(0);

	if(rc != 0){
		if(hndl->path != NULL){
			free(hndl->path);
		}
		if(hndl != NULL){
			free(hndl);
			hndl = NULL;
		}
	}
	return hndl;
}

static void elfparse_parse(struct elfparse_info *hndl) {
	ElfEhdr *ehdr = hndl->mapping;
	hndl->ehdr = ehdr;
	ElfShdr *sec = (Elf32_Shdr *)((uint8_t *)ehdr + ehdr->e_shoff);
	hndl->sec = sec;
	DBG("e_ident=%s", ehdr->e_ident);
	DBG("e_phoff=%zu", ehdr->e_phoff);
	DBG("e_shoff=%zu", ehdr->e_shoff);
	DBG("e_shentsize=%u", ehdr->e_shentsize);
	DBG("e_shnum=%u", ehdr->e_shnum);

	ElfShdr *shdr = hndl->mapping + ehdr->e_shoff;
	char *strtab = hndl->mapping + shdr[ehdr->e_shstrndx].sh_offset;
	for(int i = 0; i < ehdr->e_shnum; ++i)
	{
		ElfShdr *cur_shdr = &shdr[i];
		char *name = &strtab[cur_shdr->sh_name];
		if(!strcmp(name, ".symtab"))
		{
			hndl->symtab = hndl->mapping + cur_shdr->sh_offset;
			hndl->symtab_entries = cur_shdr->sh_size / cur_shdr->sh_entsize;
			DBG("Found symbol table (%u entries): %p", hndl->symtab_entries, hndl->symtab);
		}
		else if(!strcmp(name, ".strtab"))
		{
			hndl->strtab = hndl->mapping + cur_shdr->sh_offset;
			DBG("Found string table: %p", hndl->strtab);
		}
		else if(!strcmp(name, ".dynsym"))
		{
			hndl->dynsym = hndl->mapping + cur_shdr->sh_offset;
			hndl->dynsym_entries = cur_shdr->sh_size / cur_shdr->sh_entsize;
			DBG("Found dynsym (%u entries): %p", hndl->dynsym_entries, hndl->dynsym);
		}
		else if(!strcmp(name, ".dynstr"))
		{
			hndl->dynstr = hndl->mapping + cur_shdr->sh_offset;
			DBG("Found dynstr: %p", hndl->dynstr);
		}
	}
}

bool elfparse_needs_reloc(void *handle)
{
	struct elfparse_info *hndl = (struct elfparse_info *)handle;
	return hndl->ehdr->e_type != ET_EXEC;
}

static uint8_t *elfparse_findfunction(
	struct elfparse_info *hndl,
	char *strtab, ElfSym *symtab,
	int symtab_entries,
	const char *funcname
){
	for(int i = 0; i < symtab_entries; ++i) {
		ElfSym *sym = &symtab[i];
		char *curname = &strtab[sym->st_name];
		if(!strcmp(curname, funcname)){
			unsigned offset = (
				hndl->sec[sym->st_shndx].sh_offset
				+ sym->st_value - hndl->sec[sym->st_shndx].sh_addr
			);
			return (uint8_t *)offset;
		}
	}
	return 0;
}

void *elfparse_getfuncaddr(void *handle, const char *funcname)
{
	struct elfparse_info *hndl = (struct elfparse_info*)handle;
	uint8_t *fn = elfparse_findfunction(hndl, hndl->strtab, hndl->symtab, hndl->symtab_entries, funcname);
	if(fn){
		return fn;
	}
	DBG("Function %s not found in symtab, trying dynsym", funcname);
	fn = elfparse_findfunction(hndl, hndl->dynstr, hndl->dynsym, hndl->dynsym_entries, funcname);
	if(fn){
		return fn;
	}
	WARN("Function %s not found in symtab or dynsym", funcname);
	return 0;
#if 0
	if(hndl->ehdr->e_machine == EM_ARM) /* apply fix for Thumb functions */
		fn = (uint8_t *)((uintptr_t)fn & ~1);
#endif
}

void elfparse_destroyhandle(void *handle)
{
	struct elfparse_info *hndl = (struct elfparse_info*)handle;
	free(hndl->path);
	munmap(hndl->mapping, hndl->len);
	close(hndl->fd);
	free(hndl);
}
