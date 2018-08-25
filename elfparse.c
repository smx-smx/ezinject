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

struct elfparse_info
{
	char *path;
	int fd;
	void *mapping;
	size_t len;

	ElfW(Ehdr) *ehdr;

	char *strtab;
	ElfW(Sym) *symtab;
	int symtab_entries;

	char *dynstr;
	ElfW(Sym) *dynsym;
	int dynsym_entries;
};

void elfparse_parse(struct elfparse_info *hndl);

void *elfparse_createhandle(const char *procpath)
{
	struct elfparse_info *hndl = malloc(sizeof(struct elfparse_info));
	memset(hndl, 0, sizeof(struct elfparse_info));
	hndl->path = strdup(procpath);
	hndl->fd = open(hndl->path, O_RDONLY);
	hndl->len = lseek(hndl->fd, 0, SEEK_END);
	lseek(hndl->fd, 0, SEEK_SET);
	hndl->mapping = mmap(0, hndl->len, PROT_READ, MAP_SHARED, hndl->fd, 0);
	elfparse_parse(hndl);
	return hndl;
}

void elfparse_parse(struct elfparse_info *hndl)
{
	ElfW(Ehdr) *ehdr = hndl->mapping;
	hndl->ehdr = ehdr;

	ElfW(Shdr) *shdr = hndl->mapping + ehdr->e_shoff;
	char *strtab = hndl->mapping + shdr[ehdr->e_shstrndx].sh_offset;
	for(int i = 0; i < ehdr->e_shnum; ++i)
	{
		ElfW(Shdr) *cur_shdr = &shdr[i];
		char *name = &strtab[cur_shdr->sh_name];
		if(!strcmp(name, ".symtab"))
		{
			hndl->symtab = hndl->mapping + cur_shdr->sh_offset;
			hndl->symtab_entries = cur_shdr->sh_size / cur_shdr->sh_entsize;
		}
		else if(!strcmp(name, ".strtab"))
		{
			hndl->strtab = hndl->mapping + cur_shdr->sh_offset;
		}
		else if(!strcmp(name, ".dynsym"))
		{
			hndl->dynsym = hndl->mapping + cur_shdr->sh_offset;
			hndl->dynsym_entries = cur_shdr->sh_size / cur_shdr->sh_entsize;
		}
		else if(!strcmp(name, ".dynstr"))
		{
			hndl->dynstr = hndl->mapping + cur_shdr->sh_offset;
		}
	}
}

bool elfparse_needs_reloc(void *handle)
{
	struct elfparse_info *hndl = (struct elfparse_info *)handle;
	return hndl->ehdr->e_type != ET_EXEC;
}

char *elfparse_findfunction(char *strtab, ElfW(Sym) *symtab, int symtab_entries, const char *funcname)
{
	for(int i = 0; i < symtab_entries; ++i)
	{
		char *curname = &strtab[symtab[i].st_name];
		if(!strcmp(curname, funcname))
			return (char *)symtab[i].st_value;
	}
	return 0;
}

char *elfparse_getfuncaddr(void *handle, const char *funcname)
{
	struct elfparse_info *hndl = (struct elfparse_info*)handle;
	char *fn = elfparse_findfunction(hndl->strtab, hndl->symtab, hndl->symtab_entries, funcname);
	if(fn)
		goto ret;
	fn = elfparse_findfunction(hndl->dynstr, hndl->dynsym, hndl->dynsym_entries, funcname);
	if(fn)
		goto ret;
	return 0;
ret:
	if(hndl->ehdr->e_machine == EM_ARM) /* apply fix for Thumb functions */
		fn = (char *)((uintptr_t)fn & ~1);
	return fn;
}

void elfparse_destroyhandle(void *handle)
{
	struct elfparse_info *hndl = (struct elfparse_info*)handle;
	free(hndl->path);
	munmap(hndl->mapping, hndl->len);
	close(hndl->fd);
	free(hndl);
}
