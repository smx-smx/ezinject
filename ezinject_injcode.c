#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <sys/syscall.h>

#include "config.h"
#include "ezinject_arch.h"
#include "ezinject_injcode.h"

#define ALIGN(x) ((void *)(((uintptr_t)x + MEMALIGN) & ALIGNMSK))

#ifdef HAVE_CLONE_IO
#define CLONE_FLAGS (CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_PARENT|CLONE_THREAD|CLONE_IO)
#else
#define CLONE_FLAGS (CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_PARENT|CLONE_THREAD)
#endif

#ifdef HAVE_LIBC_DLOPEN_MODE
#define __RTLD_DLOPEN 0x80000000 /* glibc internal */
#endif

#define BR_STRTBL(br) ((char *)br + sizeof(*br) + (sizeof(char *) * br->argc))

#define EMIT_LABEL(name) \
	asm volatile( \
		".globl "name"\n" \
		name":\n" \
	)

void injected_code_start(void){}

void injected_sc(){
	EMIT_LABEL("injected_sc_start");
	EMIT_SC();
	EMIT_LABEL("injected_sc_end");
}

void injected_clone(){
	EMIT_LABEL("injected_clone_entry");

	register struct injcode_bearing *br;
	register int (*pfnChild)(void *arg);
	register void *clone_stack;
	
	EMIT_POP(br);
	EMIT_POP(pfnChild);
	EMIT_POP(clone_stack);

	br->libc_clone(pfnChild, clone_stack, CLONE_FLAGS, br);

	while(1);
}

#ifdef HAVE_DL_LOAD_SHARED_LIBRARY
inline unsigned int strlen(const char *str){
	unsigned int len = 0;
	while(*(str++)) len++;
	return len;
}

inline void *memset(void *s, int c, unsigned int n){
    unsigned char* p=s;
    while(n--){
        *p++ = (unsigned char)c;
	}
    return s;
}

int uclibc_dlopen(struct injcode_bearing *br){
	char *libdl_name = BR_STRTBL(br);
	char *userlib_name = BR_STRTBL(br) + strlen(libdl_name) + 1;

	struct elf_resolve_hdr *tpnt;

	struct dyn_elf *rpnt;
	for (rpnt = *(br->uclibc_sym_tables); rpnt && rpnt->next; rpnt = rpnt->next){
		continue;
	}

	tpnt = br->libc_dlopen(0, &rpnt, NULL, libdl_name, 0);
	if(tpnt == NULL){
		return 1;
	}

#ifdef EZ_ARCH_MIPS
	br->uclibc_mips_got_reloc(tpnt, 0);
#endif

// FIXME: how do we get this dynamically? its offset is NOT fixed
#define SYMBOL_SCOPE_OFFSET (15 * sizeof(void *))

	struct r_scope_elem *global_scope = (struct r_scope_elem *)(
		(uintptr_t)*(br->uclibc_loaded_modules) + SYMBOL_SCOPE_OFFSET
	);

	struct r_scope_elem *ls = global_scope;
	for (; ls && ls->next; ls = ls->next);
	/* Extend the global scope by adding the local scope of the dlopened DSO. */
	ls->next = (void *)(
		(uintptr_t)tpnt + SYMBOL_SCOPE_OFFSET
	);

	struct dyn_elf dyn;
	memset(&dyn, 0x00, sizeof(dyn));
	dyn.dyn = tpnt;
	if(br->uclibc_dl_fixup(&dyn, global_scope, RTLD_NOW)){
		// FIXME: we are not handling init/fini arrays
		// This means the call will likely 'fail' and warn about unresolved symbols.
		//
		// symbol 'dl_cleanup': can't resolve symbol
	}

	void (*dlopen)(const char *filename, int flag) = (void *)(
		((uintptr_t)(tpnt->loadaddr) + br->dlopen_offset)
	);
	dlopen(userlib_name, RTLD_NOW);
	return 0;
}
#endif

int clone_fn(void *arg){
	struct injcode_bearing *br = (struct injcode_bearing *)arg;
	
	int ret = 1;
	if(br->actual_dlopen != NULL){
		char *userlib_name = BR_STRTBL(br);
		ret = br->actual_dlopen(userlib_name, RTLD_NOW) != NULL;
	} else {
#if	defined(HAVE_LIBC_DLOPEN_MODE)
		char *userlib_name = BR_STRTBL(br);
		ret = br->libc_dlopen(userlib_name, RTLD_NOW | __RTLD_DLOPEN) != NULL;
#elif defined(HAVE_DL_LOAD_SHARED_LIBRARY)
		// with uclibc, we need to load libdl ourselves
		ret = uclibc_dlopen(br);
#endif
	}

	br->libc_syscall(__NR_exit, ret);

	while(1);

	// must never be reached, or we hit undefined behaviour (invalid return address)
	return 0;
}

void injected_code_end(void){}