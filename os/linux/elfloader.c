/*
 * maps an ET_DYN user library in the target without using
 * the target dynamic loader. for targets whose loader is
 * broken (eg old glibc, where dlopen stops working once the
 * symbol table gets too big) we do the loader's job here:
 *
 * parse LOADs/dynamic/relocs/symbols, mmap the segments into
 * the target, fix up the relocs, set protections, flush icache,
 * and hand init lists + crt_init + libc/libpthread addresses to
 * the payload through br->elfloader. missing NEEDED deps get
 * mapped too (depth-first, skipped when already in the target);
 * UNDEF symbols resolve through local dlopen + dlsym + dladdr,
 * matched to remote addresses by device+inode so renames and
 * symlinks don't fool us.
 *
 * arch bits (reloc types, MIPS GOT, icache flush) sit behind
 * EZ_ARCH_* switches. an unknown reloc type fails the load,
 * it is never guessed. build payload libs bind-now, JMPREL
 * is resolved up front everywhere.
 *
 * no static TLS in mapped libs: PT_TLS is refused, only the
 * real loader could do that. no symbol versioning either,
 * plain dlsym rules apply.
 */
#include "config.h"

#include <elf.h>
#include <link.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#ifdef EZ_ARCH_MIPS
#include <asm/cachectl.h>
#endif

#include "ezinject.h"
#include "ezinject_util.h"
#include "ezinject_injcode.h"
#include "log.h"
#include "common.h"

#ifndef MAP_FAILED
#define MAP_FAILED ((void *)-1)
#endif

#if UINTPTR_MAX == 0xffffffffffffffffULL
#define ELF_R_TYPE ELF64_R_TYPE
#define ELF_R_SYM ELF64_R_SYM
#else
#define ELF_R_TYPE ELF32_R_TYPE
#define ELF_R_SYM ELF32_R_SYM
#endif

#if __WORDSIZE == 64
#define ELF_ST_BIND ELF64_ST_BIND
#else
#define ELF_ST_BIND ELF32_ST_BIND
#endif

/* symbols the payload needs directly (replaces inj_fetchsym) */
static uintptr_t elf_align_down(uintptr_t v, uintptr_t a){ return v & ~(a - 1); }
static uintptr_t elf_align_up(uintptr_t v, uintptr_t a){ return (v + a - 1) & ~(a - 1); }

struct elf_file {
	int fd;
	void *map;
	size_t len;
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	ElfW(Dyn) *dyn;
	size_t dyn_cnt;
	ElfW(Sym) *dynsym;
	const char *dynstr;
	size_t dynsym_cnt;
	ElfW(Addr) link_base;	/* min p_vaddr over LOADs */
};

/* already-mapped (by us) libraries, for cycle guard + reuse */
#define ELF_MAX_MAPPED 16
struct elf_mapped {
	dev_t dev;
	ino_t ino;
	uintptr_t remote_base;
	uintptr_t bias;
	uintptr_t local_base;	/* dlopened base in injector (0 if unknown) */
	size_t local_span;	/* mapping span for range match */
};

struct elf_ctx {
	struct ezinj_ctx *ctx;
	struct injcode_bearing *br;
	uintptr_t pagesize;
	void **handles;
	size_t nhandles, handles_cap;
	struct elf_mapped mapped[ELF_MAX_MAPPED];
	size_t nmapped;
	/* fallback storage for thread-local symbols we cannot remap
	 * (errno, h_errno): one remotely-mmapped page, bump-allocated.
	 * 0 until first use. */
	uintptr_t tls_scratch;
	size_t tls_used;
};

/* file offset -> host pointer, or NULL */
static void *elf_foff(struct elf_file *f, ElfW(Off) off){
	if(off >= f->len){
		return NULL;
	}
	return (char *)f->map + off;
}

/* link vaddr -> file offset, or (ElfW(Off))-1 */
static ElfW(Off) elf_vaddr_to_off(struct elf_file *f, ElfW(Addr) vaddr){
	ElfW(Phdr) *ph = f->phdr;
	for(int i = 0; i < f->ehdr->e_phnum; i++, ph++){
		if(ph->p_type != PT_LOAD){
			continue;
		}
		if(vaddr >= ph->p_vaddr && vaddr < ph->p_vaddr + ph->p_memsz){
			return ph->p_offset + (vaddr - ph->p_vaddr);
		}
	}
	return (ElfW(Off))-1;
}

/* link vaddr -> host pointer for reading file content, or NULL */
static void *elf_vaddr_ptr(struct elf_file *f, ElfW(Addr) vaddr){
	ElfW(Off) off = elf_vaddr_to_off(f, vaddr);
	if(off == (ElfW(Off))-1){
		return NULL;
	}
	return elf_foff(f, off);
}

static int elf_parse(struct elf_file *f, const char *path){
	memset(f, 0, sizeof(*f));
	f->fd = -1;
	f->fd = open(path, O_RDONLY);
	if(f->fd < 0){
		ERR("elfloader: open(%s): %s", path, strerror(errno));
		return -1;
	}
	struct stat st;
	if(fstat(f->fd, &st) != 0){
		ERR("elfloader: fstat: %s", strerror(errno));
		close(f->fd);
		f->fd = -1;
		return -1;
	}
	f->len = (size_t)st.st_size;
	f->map = mmap(NULL, f->len, PROT_READ, MAP_PRIVATE, f->fd, 0);
	if(f->map == MAP_FAILED){
		ERR("elfloader: mmap: %s", strerror(errno));
		f->map = NULL;
		close(f->fd);
		f->fd = -1;
		return -1;
	}
	f->ehdr = (ElfW(Ehdr) *)f->map;
	if(f->len < sizeof(ElfW(Ehdr)) || memcmp(f->ehdr->e_ident, ELFMAG, SELFMAG) != 0){
		ERR("elfloader: not an ELF file");
		return -1;
	}
	if(f->ehdr->e_type != ET_DYN){
		ERR("elfloader: not a shared library (type %d)", f->ehdr->e_type);
		return -1;
	}
	INFO("elfloader: ELF machine %d, %d phdrs", f->ehdr->e_machine, f->ehdr->e_phnum);
	f->phdr = (ElfW(Phdr) *)((char *)f->map + f->ehdr->e_phoff);
	f->link_base = (ElfW(Addr))-1;
	ElfW(Phdr) *ph = f->phdr;
	for(int i = 0; i < f->ehdr->e_phnum; i++, ph++){
		if(ph->p_type == PT_LOAD && ph->p_vaddr < f->link_base){
			f->link_base = ph->p_vaddr;
		}
		if(ph->p_type == PT_DYNAMIC){
			f->dyn = (ElfW(Dyn) *)elf_foff(f, ph->p_offset);
			f->dyn_cnt = ph->p_filesz / sizeof(ElfW(Dyn));
		}
		if(ph->p_type == PT_TLS){
			ERR("elfloader: static TLS unsupported (%s needs loader cooperation)", path);
			return -1;
		}
	}
	if(!f->dyn){
		ERR("elfloader: no PT_DYNAMIC");
		return -1;
	}
	ElfW(Addr) symtab = 0, strtab = 0;
	for(size_t i = 0; i < f->dyn_cnt; i++){
		switch(f->dyn[i].d_tag){
			case DT_SYMTAB: symtab = f->dyn[i].d_un.d_ptr; break;
			case DT_STRTAB: strtab = f->dyn[i].d_un.d_ptr; break;
			case DT_SYMENT:
				if(f->dyn[i].d_un.d_val != sizeof(ElfW(Sym))){
					ERR("elfloader: bad SYMENT");
					return -1;
				}
				break;
			default: break;
		}
	}
	if(!symtab || !strtab){
		ERR("elfloader: no symtab/strtab");
		return -1;
	}
	f->dynsym = (ElfW(Sym) *)elf_vaddr_ptr(f, symtab);
	f->dynstr = (const char *)elf_vaddr_ptr(f, strtab);
	if(!f->dynsym || !f->dynstr){
		ERR("elfloader: bad symtab/strtab addrs");
		return -1;
	}
	/* dynsym count: DT_HASH nchain, else section headers */
	f->dynsym_cnt = 0;
	for(size_t i = 0; i < f->dyn_cnt; i++){
		if(f->dyn[i].d_tag == DT_HASH){
			uint32_t *hash = (uint32_t *)elf_vaddr_ptr(f, f->dyn[i].d_un.d_ptr);
			if(hash){
				f->dynsym_cnt = hash[1];
			}
			break;
		}
	}
	if(f->dynsym_cnt == 0 && f->ehdr->e_shnum != 0){
		ElfW(Shdr) *sh = (ElfW(Shdr) *)((char *)f->map + f->ehdr->e_shoff);
		for(int i = 0; i < f->ehdr->e_shnum; i++){
			if(sh[i].sh_type == SHT_DYNSYM){
				f->dynsym_cnt = sh[i].sh_size / sizeof(ElfW(Sym));
				break;
			}
		}
	}
	INFO("elfloader: %zu dynsyms", f->dynsym_cnt);
	return 0;
}

static void elf_close(struct elf_file *f){
	if(f->map){
		munmap(f->map, f->len);
	}
	if(f->fd >= 0){
		close(f->fd);
	}
	memset(f, 0, sizeof(*f));
	f->fd = -1;
}

/* is this file already mapped in target? (by device+inode). */
static int elf_target_has(struct ezinj_ctx *ctx, const char *path){
	struct stat st;
	if(stat(path, &st) != 0){
		return 0;
	}
	char line[512];
	char maps[64];
	snprintf(maps, sizeof(maps), "/proc/%u/maps", ctx->target);
	FILE *fp = fopen(maps, "r");
	if(!fp){
		return 0;
	}
	int found = 0;
	while(fgets(line, sizeof(line), fp) != NULL){
		struct ezinj_map_entry e;
		if(os_parse_maps_line(line, &e) != 0 || !e.has_path){
			continue;
		}
		struct stat mst;
		if(stat(e.path, &mst) != 0){
			continue;
		}
		if(mst.st_dev == st.st_dev && mst.st_ino == st.st_ino){
			found = 1;
			break;
		}
	}
	fclose(fp);
	return found;
}

/* resolve a host address to a remote address via dladdr + target maps.
 * Match by device+inode so renames/symlinks can't confuse us. */
static uintptr_t elf_remote_of(struct ezinj_ctx *ctx, void *local){
	Dl_info info;
	memset(&info, 0, sizeof(info));
	if(!dladdr(local, &info) || !info.dli_fname || !info.dli_fbase){
		ERR("elfloader: dladdr(%p) failed", local);
		return 0;
	}
	struct stat st;
	if(stat(info.dli_fname, &st) != 0){
		ERR("elfloader: stat(%s) failed", info.dli_fname);
		return 0;
	}
	char line[512];
	char maps[64];
	snprintf(maps, sizeof(maps), "/proc/%u/maps", ctx->target);
	FILE *fp = fopen(maps, "r");
	if(!fp){
		ERR("elfloader: fopen %s: %s", maps, strerror(errno));
		return 0;
	}
	uintptr_t rbase = 0;
	while(fgets(line, sizeof(line), fp) != NULL){
		struct ezinj_map_entry e;
		if(os_parse_maps_line(line, &e) != 0){
			continue;
		}
		if(e.offset != 0){
			continue; /* need the base mapping (file offset 0) */
		}
		if(!e.has_path){
			continue;
		}
		struct stat mst;
		if(stat(e.path, &mst) != 0){
			continue;
		}
		if(mst.st_dev == st.st_dev && mst.st_ino == st.st_ino){
			rbase = e.start;
			break;
		}
	}
	fclose(fp);
	if(!rbase){
		ERR("elfloader: %s not mapped in target", info.dli_fname);
		return 0;
	}
	uintptr_t remote = rbase + ((uintptr_t)local - (uintptr_t)info.dli_fbase);
	DBG("elfloader: %p (%s) -> remote %p", local, info.dli_fname, (void *)remote);
	return remote;
}

/* fallback address for thread-local data symbols (errno, h_errno).
 * dlsym resolves them to the injector thread's TLS instance, which
 * dladdr cannot attribute to any object, so a dev/ino remap is
 * impossible. bind them to a private zeroed word in the target
 * instead: mapped libraries then see a process-global errno
 * (pre-NPTL behavior) rather than the thread-local one. good
 * enough for what the payload needs (mutexes, thread create);
 * user code's own errno via libc is unaffected. */
static uintptr_t elf_tls_fallback(struct elf_ctx *elfm, const char *name){
	struct ezinj_ctx *ctx = elfm->ctx;
	if(!elfm->tls_scratch){
#if defined(__NR_mmap2)
		uintptr_t r = CHECK(RSCALL6(ctx, __NR_mmap2,
			NULL, elfm->pagesize,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
#elif defined(__NR_mmap)
		uintptr_t r = CHECK(RSCALL6(ctx, __NR_mmap,
			NULL, elfm->pagesize,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
#else
#error "elfloader needs __NR_mmap2 or __NR_mmap"
#endif
		if(r == 0 || r == (uintptr_t)MAP_FAILED){
			ERR("elfloader: TLS scratch mmap failed");
			return 0;
		}
		elfm->tls_scratch = r;
		elfm->tls_used = 0;
	}
	if(elfm->tls_used + 8 > (size_t)elfm->pagesize){
		ERR("elfloader: TLS scratch exhausted");
		return 0;
	}
	uintptr_t slot = elfm->tls_scratch + elfm->tls_used;
	elfm->tls_used += 8;
	WARN("elfloader: %s is thread-local, binding private word %p",
		name, (void *)slot);
	return slot;
}

/* look up an UNDEF symbol in the NEEDED handles in order,
 * then RTLD_DEFAULT. weak undefs may stay 0. */
static uintptr_t elf_resolve(struct elf_ctx *elfm, const char *name, int is_weak){
	struct ezinj_ctx *ctx = elfm->ctx;
	void *local = NULL;
	for(size_t i = 0; i < elfm->nhandles && !local; i++){
		local = dlsym(elfm->handles[i], name);
	}
	if(!local){
		local = dlsym(RTLD_DEFAULT, name);
	}
	if(!local){
		if(is_weak){
			WARN("elfloader: weak %s unresolved, binding 0", name);
			return 0;
		}
		ERR("elfloader: cannot resolve %s", name);
		return 0;
	}
	/* prefer our own mappings (anonymous: invisible in target maps) */
	for(size_t i = 0; i < elfm->nmapped; i++){
		uintptr_t lb = elfm->mapped[i].local_base;
		size_t span = elfm->mapped[i].local_span;
		if(lb && span && (uintptr_t)local >= lb && (uintptr_t)local < lb + span){
			uintptr_t remote = elfm->mapped[i].remote_base
				+ ((uintptr_t)local - lb);
			DBG("elfloader: %s (%p) -> own map %p", name, local, (void *)remote);
			return remote;
		}
	}
	uintptr_t remote = elf_remote_of(ctx, local);
	if(!remote && !is_weak){
		/* thread-local data (errno, h_errno): dlsym gives the
		 * injector thread's instance, which has no file mapping */
		if(!strcmp(name, "errno") || !strcmp(name, "h_errno")){
			remote = elf_tls_fallback(elfm, name);
		}
	}
	if(!remote && !is_weak){
		ERR("elfloader: cannot remap %s (%p)", name, local);
		return 0;
	}
	return remote;
}

/* remote word read/write helpers (native word size = target word size) */
static int elf_rread(struct ezinj_ctx *ctx, uintptr_t addr, uintptr_t *out){
	ElfW(Addr) v = 0;
	if(remote_read(ctx, &v, addr, sizeof(v)) != sizeof(v)){
		return -1;
	}
	*out = (uintptr_t)v;
	return 0;
}

static int elf_rwrite(struct ezinj_ctx *ctx, uintptr_t addr, uintptr_t val){
	ElfW(Addr) v = (ElfW(Addr))val;
	if(remote_write(ctx, addr, &v, sizeof(v)) != sizeof(v)){
		return -1;
	}
	return 0;
}

/* do one reloc from the injector. S = remote symbol value
 * (bias included), A = addend. arch-specific; an unknown
 * type is an error. */
static int elf_apply_rel(struct ezinj_ctx *ctx, unsigned type, uintptr_t loc,
	uintptr_t s, uintptr_t a)
{
	switch(type){
#if defined(EZ_ARCH_MIPS)
	case R_MIPS_NONE:
		return 0;
	case R_MIPS_32:
	case R_MIPS_REL32:
		return elf_rwrite(ctx, loc, s + a);
#ifdef R_MIPS_GLOB_DAT
	case R_MIPS_GLOB_DAT:
		return elf_rwrite(ctx, loc, s);
#endif
#ifdef R_MIPS_JUMP_SLOT
	case R_MIPS_JUMP_SLOT:
		return elf_rwrite(ctx, loc, s);
#endif
#elif defined(EZ_ARCH_X86_64) || defined(EZ_ARCH_AMD64)
	case R_X86_64_NONE:
		return 0;
	case R_X86_64_GLOB_DAT:
	case R_X86_64_JUMP_SLOT:
		return elf_rwrite(ctx, loc, s);
	case R_X86_64_RELATIVE:
		return elf_rwrite(ctx, loc, s + a);
#elif defined(EZ_ARCH_I386)
	case R_386_NONE:
		return 0;
	case R_386_GLOB_DAT:
	case R_386_JMP_SLOT:
		return elf_rwrite(ctx, loc, s);
	case R_386_RELATIVE:
		return elf_rwrite(ctx, loc, s + a);
#elif defined(EZ_ARCH_AARCH64)
	case 0: /* R_AARCH64_NONE */
		return 0;
	case 1027: /* R_AARCH64_RELATIVE */
		return elf_rwrite(ctx, loc, s + a);
	case 1025: /* R_AARCH64_GLOB_DAT */
	case 1026: /* R_AARCH64_JUMP_SLOT */
		return elf_rwrite(ctx, loc, s);
#elif defined(EZ_ARCH_ARM)
	case 0: /* R_ARM_NONE */
		return 0;
	case 23: /* R_ARM_RELATIVE */
		return elf_rwrite(ctx, loc, s + a);
	case 21: /* R_ARM_GLOB_DAT */
	case 22: /* R_ARM_JUMP_SLOT */
		return elf_rwrite(ctx, loc, s);
#endif
	default:
		break;
	}
	ERR("elfloader: unhandled reloc type %u (arch needs a case above)", type);
	return -1;
}

/* apply one REL/RELA (or JMPREL) table host-side */
static int elf_apply_table(struct elf_ctx *elfm, struct elf_file *f,
	uintptr_t remote_base, uintptr_t bias,
	ElfW(Addr) rel, size_t count, size_t relent, int is_rela)
{
	struct ezinj_ctx *ctx = elfm->ctx;
	for(size_t i = 0; i < count; i++){
		uintptr_t loc, s = 0, a = 0;
		unsigned type;
		const char *symname = NULL;
		int symidx = 0, is_weak = 0;
		if(is_rela){
			ElfW(Rela) *r = (ElfW(Rela) *)elf_vaddr_ptr(f, rel + i * relent);
			if(!r){
				ERR("elfloader: bad RELA addr");
				return -1;
			}
			type = ELF_R_TYPE(r->r_info);
			symidx = ELF_R_SYM(r->r_info);
			a = (uintptr_t)r->r_addend;
			loc = remote_base + (r->r_offset - f->link_base);
		} else {
			ElfW(Rel) *r = (ElfW(Rel) *)elf_vaddr_ptr(f, rel + i * relent);
			if(!r){
				ERR("elfloader: bad REL addr");
				return -1;
			}
			type = ELF_R_TYPE(r->r_info);
			symidx = ELF_R_SYM(r->r_info);
			loc = remote_base + (r->r_offset - f->link_base);
			if(elf_rread(ctx, loc, &a) != 0){
				ERR("elfloader: cannot read addend at %p", (void *)loc);
				return -1;
			}
		}
		if(symidx != 0){
			if((size_t)symidx >= f->dynsym_cnt){
				ERR("elfloader: bad symidx %d", symidx);
				return -1;
			}
			ElfW(Sym) *sym = &f->dynsym[symidx];
			symname = f->dynstr + sym->st_name;
			if(sym->st_shndx != SHN_UNDEF){
				s = bias + sym->st_value;
			} else {
				is_weak = (ELF_ST_BIND(sym->st_info) == STB_WEAK);
				s = elf_resolve(elfm, symname, is_weak);
				if(!s && !is_weak){
					return -1;
				}
			}
		} else {
			s = bias; /* RELATIVE */
		}
		if(elf_apply_rel(ctx, type, loc, s, a) != 0){
			ERR("elfloader: reloc failed (%s type %u)", symname ? symname : "-", type);
			return -1;
		}
	}
	return 0;
}

/* map one library, NEEDED deps first (depth-first). on success
 * the lib's initializers are appended to br (deps first) and
 * base/bias are returned. */
/* find a SONAME: LD_LIBRARY_PATH, then the usual dirs.
 * 0 and full path in out on success. */
static int elf_find_file(const char *soname, char *out, size_t outsz){
	if(strchr(soname, '/')){
		if(access(soname, R_OK) == 0){
			snprintf(out, outsz, "%s", soname);
			return 0;
		}
		return -1;
	}
	const char *ldlp = getenv("LD_LIBRARY_PATH");
	if(ldlp && *ldlp){
		char *copy = strdup(ldlp);
		if(copy){
			char *save = NULL;
			for(char *d = strtok_r(copy, ":", &save); d;
				d = strtok_r(NULL, ":", &save)){
				snprintf(out, outsz, "%s/%s", d, soname);
				if(access(out, R_OK) == 0){
					free(copy);
					return 0;
				}
			}
			free(copy);
		}
	}
	static const char *dirs[] = { "/lib", "/usr/lib", "/usr/local/lib", NULL };
	for(int i = 0; dirs[i]; i++){
		snprintf(out, outsz, "%s/%s", dirs[i], soname);
		if(access(out, R_OK) == 0){
			return 0;
		}
	}
	return -1;
}
static int elf_map_one(struct elf_ctx *elfm, const char *path, int depth,
	uintptr_t *out_base, uintptr_t *out_bias)
{
	struct ezinj_ctx *ctx = elfm->ctx;
	struct injcode_bearing *br = NULL;
	/* br is filled by the driver; here we use elfm->br */
	br = elfm->br;
	struct elf_file f;
	uintptr_t remote_base = 0, bias = 0;
	uintptr_t pagesize = elfm->pagesize;

	if(depth > 8){
		ERR("elfloader: dependency depth exceeded (%s)", path);
		return -1;
	}
	/* cycle guard + reuse */
	{
		struct stat st;
		if(stat(path, &st) == 0){
			for(size_t i = 0; i < elfm->nmapped; i++){
				if(elfm->mapped[i].dev == st.st_dev && elfm->mapped[i].ino == st.st_ino){
					*out_base = elfm->mapped[i].remote_base;
					*out_bias = elfm->mapped[i].bias;
					return 0;
				}
			}
		}
	}

	if(elf_parse(&f, path) != 0){
		return -1;
	}

	/* collect NEEDED names, dlopen locally (for symbol scope) */
	const char *need_names[32];
	size_t nneeds = 0;
	for(size_t i = 0; i < f.dyn_cnt; i++){
		if(f.dyn[i].d_tag != DT_NEEDED){
			continue;
		}
		if(nneeds >= 32){
			ERR("elfloader: too many NEEDED");
			goto out;
		}
		need_names[nneeds++] = f.dynstr + f.dyn[i].d_un.d_val;
	}
	for(size_t i = 0; i < nneeds; i++){
		INFO("elfloader: NEEDED %s", need_names[i]);
		void *h = dlopen(need_names[i], RTLD_NOW | RTLD_GLOBAL);
		if(!h){
			ERR("elfloader: dlopen(%s) failed: %s", need_names[i], dlerror());
			goto out;
		}
		if(elfm->nhandles >= elfm->handles_cap){
			elfm->handles_cap = elfm->handles_cap ? elfm->handles_cap * 2 : 8;
			void **nh = realloc(elfm->handles, elfm->handles_cap * sizeof(*nh));
			if(!nh){
				ERR("elfloader: realloc");
				goto out;
			}
			elfm->handles = nh;
		}
		elfm->handles[elfm->nhandles++] = h;
	}


/* map the NEEDED deps missing from the target (the ones already
 * there are left alone). a dep needing static TLS can't be done
 * without the real loader, so bail (elf_parse rejects PT_TLS). */
	for(size_t i = 0; i < nneeds; i++){
		char deppath[512];
		if(elf_find_file(need_names[i], deppath, sizeof(deppath)) != 0){
			INFO("elfloader: NEEDED %s file not found, assuming present", need_names[i]);
			continue;
		}
		if(elf_target_has(ctx, deppath)){
			INFO("elfloader: NEEDED %s present in target, reusing", need_names[i]);
			continue;
		}
		INFO("elfloader: NEEDED %s missing in target, mapping %s (depth %d)",
			need_names[i], deppath, depth + 1);
		uintptr_t db = 0, di = 0;
		if(elf_map_one(elfm, deppath, depth + 1, &db, &di) != 0){
			ERR("elfloader: failed to map dependency %s", deppath);
			goto out;
		}
		(void)db; (void)di;
	}

	/* total span + remote mmap (RWX first, protect per-seg later) */
	{
		ElfW(Addr) lo = (ElfW(Addr))-1, hi = 0;
		ElfW(Phdr) *ph = f.phdr;
		for(int i = 0; i < f.ehdr->e_phnum; i++, ph++){
			if(ph->p_type != PT_LOAD){
				continue;
			}
			if(ph->p_vaddr < lo){
				lo = ph->p_vaddr;
			}
			if(ph->p_vaddr + ph->p_memsz > hi){
				hi = ph->p_vaddr + ph->p_memsz;
			}
		}
		if(lo == (ElfW(Addr))-1){
			ERR("elfloader: no LOAD segments");
			goto out;
		}
		uintptr_t span_lo = elf_align_down(lo, pagesize);
		uintptr_t span_hi = elf_align_up(hi, pagesize);
		INFO("elfloader: mapping %s %zu bytes", path, (size_t)(span_hi - span_lo));
#if defined(__NR_mmap2)
		uintptr_t r = CHECK(RSCALL6(ctx, __NR_mmap2,
			NULL, span_hi - span_lo,
			PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
#elif defined(__NR_mmap)
		uintptr_t r = CHECK(RSCALL6(ctx, __NR_mmap,
			NULL, span_hi - span_lo,
			PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
#else
#error "elfloader needs __NR_mmap2 or __NR_mmap"
#endif
		if(r == 0 || r == (uintptr_t)MAP_FAILED){
			ERR("elfloader: remote mmap failed");
			goto out;
		}
		remote_base = r + (lo - span_lo);
		bias = remote_base - f.link_base;
		INFO("elfloader: remote base %p (bias %p)", (void *)remote_base, (void *)bias);
	}

	/* remember for cycle guard + reuse (+ local range for remap) */
	{
		struct stat st;
		if(stat(path, &st) == 0 && elfm->nmapped < ELF_MAX_MAPPED){
			elfm->mapped[elfm->nmapped].dev = st.st_dev;
			elfm->mapped[elfm->nmapped].ino = st.st_ino;
			elfm->mapped[elfm->nmapped].remote_base = remote_base;
			elfm->mapped[elfm->nmapped].bias = bias;
			elfm->mapped[elfm->nmapped].local_base = 0;
			elfm->mapped[elfm->nmapped].local_span = 0;
			/* local base+span: dlopen (refcounted, harmless) + dlinfo
			 * (dladdr fallback: dlinfo needs link_map support) */
			void *lh = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
			if(!lh){
				ERR("elfloader: dlopen(%s) for local base failed: %s", path, dlerror());
			}
			if(lh){
				if(elfm->nhandles >= elfm->handles_cap){
					elfm->handles_cap = elfm->handles_cap ? elfm->handles_cap * 2 : 8;
					void **nh = realloc(elfm->handles,
						elfm->handles_cap * sizeof(*nh));
					if(nh){
						elfm->handles = nh;
						elfm->handles[elfm->nhandles++] = lh;
					}
				} else {
					elfm->handles[elfm->nhandles++] = lh;
				}
			{
				uintptr_t lbase = 0;
#ifdef RTLD_DI_LINKMAP
				struct link_map *lm = NULL;
				if(dlinfo(lh, RTLD_DI_LINKMAP, &lm) == 0 && lm && lm->l_addr){
					lbase = (uintptr_t)lm->l_addr;
				}
#endif
				if(!lbase){
					/* fallback: dladdr of first defined global */
					for(size_t di = 0; di < f.dynsym_cnt && !lbase; di++){
						ElfW(Sym) *sy = &f.dynsym[di];
						if(sy->st_shndx == SHN_UNDEF){
							continue;
						}
						if(ELF_ST_BIND(sy->st_info) == STB_LOCAL){
							continue;
						}
						void *a = dlsym(lh, f.dynstr + sy->st_name);
						if(!a){
							continue;
						}
						Dl_info dli;
						memset(&dli, 0, sizeof(dli));
						if(dladdr(a, &dli) && dli.dli_fbase){
							lbase = (uintptr_t)dli.dli_fbase;
						}
					}
				}
				if(lbase){
					ElfW(Addr) xlo = (ElfW(Addr))-1, xhi = 0;
					ElfW(Phdr) *xph = f.phdr;
					for(int xi = 0; xi < f.ehdr->e_phnum; xi++, xph++){
						if(xph->p_type != PT_LOAD){
							continue;
						}
						if(xph->p_vaddr < xlo){
							xlo = xph->p_vaddr;
						}
						if(xph->p_vaddr + xph->p_memsz > xhi){
							xhi = xph->p_vaddr + xph->p_memsz;
						}
					}
					elfm->mapped[elfm->nmapped].local_base = lbase;
					elfm->mapped[elfm->nmapped].local_span =
						(size_t)elf_align_up(xhi - xlo, elfm->pagesize);
				}
			}
			}
			INFO("elfloader: recorded %s local [%p+%zu] -> remote %p",
				path, (void *)elfm->mapped[elfm->nmapped].local_base,
				elfm->mapped[elfm->nmapped].local_span,
				(void *)elfm->mapped[elfm->nmapped].remote_base);
			elfm->nmapped++;
		}
	}

	/* write LOAD contents + zero bss */
	{
		ElfW(Phdr) *ph = f.phdr;
		for(int i = 0; i < f.ehdr->e_phnum; i++, ph++){
			if(ph->p_type != PT_LOAD){
				continue;
			}
			uintptr_t dest = remote_base + (ph->p_vaddr - f.link_base);
			void *src = elf_foff(&f, ph->p_offset);
			if(!src){
				ERR("elfloader: bad LOAD file range");
				goto out_unmap;
			}
			if(remote_write(ctx, dest, src, ph->p_filesz) != (size_t)ph->p_filesz){
				ERR("elfloader: remote_write LOAD failed");
				goto out_unmap;
			}
			if(ph->p_memsz > ph->p_filesz){
				uintptr_t zaddr = dest + ph->p_filesz;
				size_t zlen = ph->p_memsz - ph->p_filesz;
				char zbuf[1024];
				memset(zbuf, 0, sizeof(zbuf));
				while(zlen > 0){
					size_t n = zlen > sizeof(zbuf) ? sizeof(zbuf) : zlen;
					if(remote_write(ctx, zaddr, zbuf, n) != n){
						ERR("elfloader: remote_write bss failed");
						goto out_unmap;
					}
					zaddr += n;
					zlen -= n;
				}
			}
		}
	}

	/* explicit REL/RELA tables (generic) */
	for(size_t di = 0; di < f.dyn_cnt; di++){
		if(f.dyn[di].d_tag != DT_REL && f.dyn[di].d_tag != DT_RELA){
			continue;
		}
		int is_rela = (f.dyn[di].d_tag == DT_RELA);
		ElfW(Addr) rel = 0, relsz = 0, relent = 0;
		for(size_t i = 0; i < f.dyn_cnt; i++){
			if(is_rela && f.dyn[i].d_tag == DT_RELA){ rel = f.dyn[i].d_un.d_ptr; }
			if(is_rela && f.dyn[i].d_tag == DT_RELASZ){ relsz = f.dyn[i].d_un.d_val; }
			if(is_rela && f.dyn[i].d_tag == DT_RELAENT){ relent = f.dyn[i].d_un.d_val; }
			if(!is_rela && f.dyn[i].d_tag == DT_REL){ rel = f.dyn[i].d_un.d_ptr; }
			if(!is_rela && f.dyn[i].d_tag == DT_RELSZ){ relsz = f.dyn[i].d_un.d_val; }
			if(!is_rela && f.dyn[i].d_tag == DT_RELENT){ relent = f.dyn[i].d_un.d_val; }
		}
		if(!rel || !relsz || !relent){
			continue;
		}
		size_t count = relsz / relent;
		INFO("elfloader: %zu %s relocs", count, is_rela ? "RELA" : "REL");
		if(elf_apply_table(elfm, &f, remote_base, bias, rel, count, relent, is_rela) != 0){
			goto out_unmap;
		}
	}

	/* JMPREL (PLT): resolve everything up front, no lazy binding */
	{
		ElfW(Addr) jmprel = 0, pltrelsz = 0, pltrel = DT_REL;
		for(size_t i = 0; i < f.dyn_cnt; i++){
			if(f.dyn[i].d_tag == DT_JMPREL){ jmprel = f.dyn[i].d_un.d_ptr; }
			if(f.dyn[i].d_tag == DT_PLTRELSZ){ pltrelsz = f.dyn[i].d_un.d_val; }
			if(f.dyn[i].d_tag == DT_PLTREL){ pltrel = f.dyn[i].d_un.d_val; }
		}
		if(jmprel && pltrelsz){
			int is_rela = (pltrel == DT_RELA);
			size_t relent = is_rela ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel));
			size_t count = pltrelsz / relent;
			INFO("elfloader: %zu JMPREL relocs", count);
			if(elf_apply_table(elfm, &f, remote_base, bias, jmprel, count, relent, is_rela) != 0){
				goto out_unmap;
			}
		}
	}

#if defined(EZ_ARCH_MIPS)
	/* MIPS lazy slots have no static relocs, so fill the global GOT
	 * from dynsym order (LOCAL_GOTNO/GOTSYM/SYMTABNO), the way the
	 * loader does with BIND_NOW. then bias the local GOT and fix
	 * GOT[0] (_DYNAMIC) and GOT[1] (0: no link_map, nothing lazy
	 * left). local GOT entries are implicitly RELATIVE per the
	 * MIPS psABI. */
	{
		ElfW(Addr) pltgot = 0, local_gotno = 0, gotsym = 0, symtabno = 0;
		for(size_t i = 0; i < f.dyn_cnt; i++){
			switch(f.dyn[i].d_tag){
				case DT_PLTGOT: pltgot = f.dyn[i].d_un.d_ptr; break;
				case DT_MIPS_LOCAL_GOTNO: local_gotno = f.dyn[i].d_un.d_val; break;
				case DT_MIPS_GOTSYM: gotsym = f.dyn[i].d_un.d_val; break;
				case DT_MIPS_SYMTABNO: symtabno = f.dyn[i].d_un.d_val; break;
				default: break;
			}
		}
		if(pltgot && symtabno > gotsym){
			INFO("elfloader: MIPS GOT walk (%u globals)",
				(unsigned)(symtabno - gotsym));
			int ok = 1;
			for(ElfW(Addr) i = 0; i < symtabno - gotsym; i++){
				if(gotsym + i >= f.dynsym_cnt){
					ERR("elfloader: GOTSYM out of range");
					ok = 0;
					break;
				}
				ElfW(Sym) *sym = &f.dynsym[gotsym + i];
				const char *name = f.dynstr + sym->st_name;
				uintptr_t addr;
				if(sym->st_shndx != SHN_UNDEF){
					addr = bias + sym->st_value;
				} else {
					int is_weak = (ELF_ST_BIND(sym->st_info) == STB_WEAK);
					addr = elf_resolve(elfm, name, is_weak);
					if(!addr && !is_weak){
						ok = 0;
						break;
					}
				}
				uintptr_t slot = remote_base + (pltgot - f.link_base)
					+ (local_gotno + i) * sizeof(ElfW(Addr));
				if(elf_rwrite(elfm->ctx, slot, addr) != 0){
					ERR("elfloader: GOT fill failed");
					ok = 0;
					break;
				}
			}
			if(!ok){
				goto out_unmap;
			}
			/* local GOT[2..local_gotno): add load bias (implicit RELATIVE).
			 * GOT[0] = _DYNAMIC, GOT[1] = 0 (no link_map; lazy unused). */
			{
				ElfW(Addr) dynvaddr = 0;
				ElfW(Phdr) *ph = f.phdr;
				for(int i = 0; i < f.ehdr->e_phnum; i++, ph++){
					if(ph->p_type == PT_DYNAMIC){
						dynvaddr = ph->p_vaddr;
						break;
					}
				}
				uintptr_t gotbase = remote_base + (pltgot - f.link_base);
				if(elf_rwrite(elfm->ctx, gotbase, bias + dynvaddr) != 0
					|| elf_rwrite(elfm->ctx, gotbase + sizeof(ElfW(Addr)), 0) != 0){
					ERR("elfloader: GOT[0/1] fill failed");
					goto out_unmap;
				}
				for(ElfW(Addr) i = 2; i < local_gotno; i++){
					uintptr_t slot = gotbase + i * sizeof(ElfW(Addr));
					uintptr_t cur = 0;
					if(elf_rread(elfm->ctx, slot, &cur) != 0){
						ERR("elfloader: local GOT read failed");
						goto out_unmap;
					}
					if(elf_rwrite(elfm->ctx, slot, cur + bias) != 0){
						ERR("elfloader: local GOT bias failed");
						goto out_unmap;
					}
				}
				INFO("elfloader: MIPS local GOT biased (%u entries)",
					(unsigned)local_gotno);
			}
		}
	}
#endif

	/* protect segments (RX / RO-RELRO) */
	{
		ElfW(Phdr) *ph = f.phdr;
		for(int i = 0; i < f.ehdr->e_phnum; i++, ph++){
			if(ph->p_type != PT_LOAD){
				continue;
			}
			int prot = 0;
			if(ph->p_flags & PF_R){ prot |= PROT_READ; }
			if(ph->p_flags & PF_W){ prot |= PROT_WRITE; }
			if(ph->p_flags & PF_X){ prot |= PROT_EXEC; }
			uintptr_t dest = remote_base + (ph->p_vaddr - f.link_base);
			uintptr_t a = elf_align_down(dest, pagesize);
			uintptr_t b = elf_align_up(dest + ph->p_memsz, pagesize);
			if(CHECK(RSCALL3(ctx, SYS_mprotect, a, b - a, prot)) != 0){
				ERR("elfloader: remote mprotect failed");
				goto out_unmap;
			}
		}
		ph = f.phdr;
		for(int i = 0; i < f.ehdr->e_phnum; i++, ph++){
			if(ph->p_type != PT_GNU_RELRO){
				continue;
			}
			uintptr_t dest = remote_base + (ph->p_vaddr - f.link_base);
			uintptr_t a = elf_align_down(dest, pagesize);
			uintptr_t b = elf_align_up(dest + ph->p_memsz, pagesize);
			if(CHECK(RSCALL3(ctx, SYS_mprotect, a, b - a, PROT_READ)) != 0){
				ERR("elfloader: remote mprotect RELRO failed");
				goto out_unmap;
			}
		}
	}

	/* icache flush where the architecture needs it (MIPS) */
#if defined(EZ_ARCH_MIPS) && defined(SYS_cacheflush)
	{
		ElfW(Phdr) *ph = f.phdr;
		for(int i = 0; i < f.ehdr->e_phnum; i++, ph++){
			if(ph->p_type != PT_LOAD || !(ph->p_flags & PF_X)){
				continue;
			}
			uintptr_t dest = remote_base + (ph->p_vaddr - f.link_base);
			if(CHECK(RSCALL3(ctx, SYS_cacheflush, dest, ph->p_memsz, BCACHE)) != 0){
				ERR("elfloader: remote cacheflush failed");
				goto out_unmap;
			}
		}
	}
#else
	INFO("elfloader: no icache flush on this arch");
#endif

	/* record initializers (deps already appended theirs: deps-first) */
	{
		if(br->elfloader.ninit >= EZ_ELFLOADER_MAX_INIT){
			ERR("elfloader: too many initializers");
			goto out_unmap;
		}
		ElfW(Addr) init = 0, init_array = 0, init_arraysz = 0;
		for(size_t i = 0; i < f.dyn_cnt; i++){
			switch(f.dyn[i].d_tag){
				case DT_INIT: init = f.dyn[i].d_un.d_ptr; break;
				case DT_INIT_ARRAY: init_array = f.dyn[i].d_un.d_ptr; break;
				case DT_INIT_ARRAYSZ: init_arraysz = f.dyn[i].d_un.d_val; break;
				default: break;
			}
		}
		int slot = br->elfloader.ninit++;
		br->elfloader.inits[slot].init = init ? (void *)(bias + init) : NULL;
		br->elfloader.inits[slot].init_array = init_array ? (void *)(bias + init_array) : NULL;
		br->elfloader.inits[slot].init_arraysz = init_arraysz;
	}

	*out_base = remote_base;
	*out_bias = bias;
	elf_close(&f);
	return 0;

out_unmap:
	{
		ElfW(Addr) lo = (ElfW(Addr))-1, hi = 0;
		ElfW(Phdr) *ph = f.phdr;
		for(int i = 0; i < f.ehdr->e_phnum; i++, ph++){
			if(ph->p_type != PT_LOAD){
				continue;
			}
			if(ph->p_vaddr < lo){
				lo = ph->p_vaddr;
			}
			if(ph->p_vaddr + ph->p_memsz > hi){
				hi = ph->p_vaddr + ph->p_memsz;
			}
		}
		if(remote_base){
			RSCALL2(ctx, __NR_munmap,
				elf_align_down(remote_base, pagesize),
				elf_align_up(hi - lo, pagesize));
		}
	}
	elf_close(&f);
	return -1;

out:
	elf_close(&f);
	return -1;
}

EZAPI elfloader_load(struct ezinj_ctx *ctx, struct injcode_bearing *br, const char *libpath){
	struct elf_ctx elfm;
	uintptr_t base = 0, bias = 0;
	int rc = -1;

	memset(&elfm, 0, sizeof(elfm));
	elfm.ctx = ctx;
	elfm.br = br;
	elfm.pagesize = ctx->pagesize ? ctx->pagesize : 4096;

	char *realpath = os_realpath(libpath);
	if(!realpath){
		ERR("elfloader: realpath(%s) failed", libpath);
		return -1;
	}
	if(elf_map_one(&elfm, realpath, 0, &base, &bias) != 0){
		free(realpath);
		goto out;
	}
	free(realpath);

	/* crt_init and the symbols the payload needs are looked up
	 * in the top lib first (its own exports), then in the dep
	 * closure */
	{
		struct elf_file f;
		memset(&f, 0, sizeof(f));
		/* re-parse top lib read-only for its dynsym (cheap, no mapping) */
		char *rp2 = os_realpath(libpath);
		if(rp2 && elf_parse(&f, rp2) == 0){
			uintptr_t crt_init = 0;
			for(size_t i = 0; i < f.dynsym_cnt; i++){
				if(!strcmp(f.dynstr + f.dynsym[i].st_name, "crt_init")
					&& f.dynsym[i].st_shndx != SHN_UNDEF){
					crt_init = bias + f.dynsym[i].st_value;
					break;
				}
			}
			elf_close(&f);
			if(!crt_init){
				ERR("elfloader: crt_init not exported");
				goto out_unmap_top;
			}
			br->manual_use = 1;
			br->elfloader.base = (void *)base;
			br->elfloader.bias = bias;
			br->elfloader.crt_init = (void *)crt_init;
			INFO("elfloader: base %p crt_init %p ninit=%d",
				(void *)base, (void *)crt_init, br->elfloader.ninit);
		}
		if(rp2){
			free(rp2);
		}
		if(!br->manual_use){
			goto out_unmap_top;
		}
		static const struct { const char *name; size_t off; } needs[] = {
			{ "dlerror", __builtin_offsetof(struct injcode_elfloader, lib_dlerror) },
			{ "pthread_mutex_init", __builtin_offsetof(struct injcode_elfloader, lib_pthread_mutex_init) },
			{ "pthread_mutex_lock", __builtin_offsetof(struct injcode_elfloader, lib_pthread_mutex_lock) },
			{ "pthread_mutex_unlock", __builtin_offsetof(struct injcode_elfloader, lib_pthread_mutex_unlock) },
			{ "pthread_cond_init", __builtin_offsetof(struct injcode_elfloader, lib_pthread_cond_init) },
			{ "pthread_cond_wait", __builtin_offsetof(struct injcode_elfloader, lib_pthread_cond_wait) },
			{ NULL, 0 }
		};
		for(int i = 0; needs[i].name; i++){
			uintptr_t r = 0;
			void *local = NULL;
			for(size_t k = 0; k < elfm.nhandles && !local; k++){
				local = dlsym(elfm.handles[k], needs[i].name);
			}
			if(!local){
				local = dlsym(RTLD_DEFAULT, needs[i].name);
			}
			if(!local){
				ERR("elfloader: cannot resolve payload need %s", needs[i].name);
				goto out_unmap_top;
			}
			r = elf_remote_of(ctx, local);
			if(!r){
				goto out_unmap_top;
			}
			*(void **)((char *)&br->elfloader + needs[i].off) = (void *)r;
			DBG("elfloader: payload need %s -> %p", needs[i].name, (void *)r);
		}
	}

	rc = 0;
	goto out;

out_unmap_top:
	br->manual_use = 0;
out:
	if(rc != 0 && elfm.tls_scratch){
		RSCALL2(ctx, __NR_munmap, elfm.tls_scratch, elfm.pagesize);
	}
	for(size_t i = 0; i < elfm.nhandles; i++){
		dlclose(elfm.handles[i]);
	}
	free(elfm.handles);
	return rc;
}
