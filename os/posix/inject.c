/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <stdlib.h>
#include "config.h"

#ifdef EZ_TARGET_POSIX
#include <sys/syscall.h>
#include <sys/mman.h>
#endif

#ifdef EZ_TARGET_WINDOWS
#include "win32_syscalls.h"
#endif

#include "ezinject.h"
#include "log.h"

#include "ezinject_util.h"
#include "ezinject_compat.h"

ez_region region_sc_code = {
	.start = (void *)&__start_syscall,
	.end = (void *)&__stop_syscall
};

// remote base of syscall code section
static uintptr_t r_current_sc_base;

#ifdef HAVE_SYSCALLS
static off_t sc_wrapper_offset;
#endif

#ifdef EZ_TARGET_LINUX
static off_t sc_mmap_offset;
static off_t sc_open_offset;
static off_t sc_read_offset;
#endif

#ifdef EZ_TARGET_WINDOWS
static off_t sc_virtualalloc_offset;
static off_t sc_virtualfree_offset;
#endif

/**
 * layout of injected shellcode
 *
 * ==================
 * trampoline
 * - trampoline_entry
 * ==================
 * syscall/sc section
 * - injected_sc6
 * - injected_sc_wrapper
 * ==================
 **/

/** trampoline function **/
static off_t trampoline_offset;
static size_t trampoline_size;
/** trampoline naked entry code addr **/
static off_t trampoline_entry_label;

/** shellcode for system calls **/
static off_t sc_offset;
static size_t sc_size;

static off_t trap_offset_start;
static off_t trap_offset_stop;

#ifdef EZ_TARGET_POSIX
static off_t sc_fn_offset;
#endif

static void *code_data(void *code){
#if defined(EZ_ARCH_ARM) && defined(USE_ARM_THUMB)
	return (void *)(UPTR(code) & ~1);
#else
	return code;
#endif
}

/**
 * setup static shellcode invariants (offsets)
 **/
static void _remote_sc_setup_offsets(){
#ifdef EZ_TARGET_POSIX
	sc_fn_offset = PTRDIFF(&injected_sc6, region_sc_code.start);
#endif

#ifdef HAVE_SYSCALLS
	sc_wrapper_offset = PTRDIFF(&injected_sc_wrapper, region_sc_code.start);
#endif

#ifdef EZ_TARGET_LINUX
	sc_mmap_offset = PTRDIFF(&injected_mmap, region_sc_code.start);
	sc_open_offset = PTRDIFF(&injected_open, region_sc_code.start);
	sc_read_offset = PTRDIFF(&injected_read, region_sc_code.start);
#endif

#ifdef EZ_TARGET_WINDOWS
	sc_virtualalloc_offset = PTRDIFF(&injected_virtual_alloc, region_sc_code.start);
	sc_virtualfree_offset = PTRDIFF(&injected_virtual_free, region_sc_code.start);
#endif

	trap_offset_start = PTRDIFF(&injected_sc_trap_start, region_sc_code.start);
	trap_offset_stop = PTRDIFF(&injected_sc_trap_stop, region_sc_code.start);

	// always at the beginning of the shellcode
	trampoline_offset = 0;
	trampoline_size = (size_t)WORDALIGN(
		PTRDIFF(code_data(&trampoline_exit), code_data(&trampoline))
	);

	trampoline_entry_label = PTRDIFF(code_data(&trampoline_entry), code_data(&trampoline));

	// shellcode section after the trampoline
	sc_offset = trampoline_offset + trampoline_size;
	sc_size = (size_t)WORDALIGN(
		REGION_LENGTH(region_sc_code)
	);
}

uintptr_t _remote_sc_addr(struct ezinj_ctx *ctx, uintptr_t addr){
	off_t rela_offset = PTRDIFF(addr, region_sc_code.start);
	return r_current_sc_base + rela_offset;
}

uintptr_t _remote_sc_base(struct ezinj_ctx *ctx, int flags, ssize_t size){
	uintptr_t sc_base = 0;
	if((flags & SC_ALLOC_ELFHDR) == SC_ALLOC_ELFHDR){
#if defined(EZ_TARGET_DARWIN)
		sc_base = remote_pl_alloc(ctx, size);
#else
		//sc_base = (uintptr_t)get_base(ctx->target, NULL, NULL);
		sc_base = ctx->r_xpage_base;
#endif
	} else if((flags & SC_ALLOC_MMAP) == SC_ALLOC_MMAP){
#if defined(EZ_TARGET_POSIX)
		sc_base = CHECK(RSCALL6(ctx, __NR_mmap2,
			0, size, PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_SHARED | MAP_ANONYMOUS,
			-1, 0));
		if(sc_base == (uintptr_t)MAP_FAILED){
			sc_base = 0;
		}
#elif defined(EZ_TARGET_WINDOWS)
		sc_base = RSCALL4(ctx, __NR_mmap,
			NULL,
			size,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		);
#else
#error "Unsupported platform"
#endif
	}
	else {
		ERR("invalid flags");
		return -1;
	}

	return sc_base;
}

#ifdef HAVE_SYSCALLS
/**
 * Get the address of the call wrapper
 **/
uintptr_t get_wrapper_address(struct ezinj_ctx *ctx){
	uintptr_t sc_wrapper_offset = PTRDIFF(&injected_sc_wrapper, region_sc_code.start);
	return r_current_sc_base + sc_wrapper_offset;
}
#endif

uintptr_t remote_sc_get_trap_start(){
	return r_current_sc_base + trap_offset_start;
}
uintptr_t remote_sc_get_trap_stop(){
	return r_current_sc_base + trap_offset_stop;
}

EZAPI remote_sc_alloc(struct ezinj_ctx *ctx, int flags, uintptr_t *out_sc_base){
	_remote_sc_setup_offsets();

	ssize_t dataLength = sc_size + trampoline_size;
	uintptr_t sc_base = _remote_sc_base(ctx, flags, dataLength);
	if(sc_base == 0){
		ERR("failed to obtain sc base");
		return -1;
	}


	if((flags & SC_ALLOC_ELFHDR) == SC_ALLOC_ELFHDR){
		ctx->saved_sc_data = calloc(dataLength, 1);
		ctx->saved_sc_size = dataLength;

		if(remote_read(ctx, ctx->saved_sc_data, sc_base, dataLength) != dataLength){
			PERROR("failed to backup data");
			return -1;
		}
	}

	// build shellcode
	uint8_t *payload = calloc(1, dataLength);
	// copy trampoline function
	memcpy(
		payload + trampoline_offset,
		code_data(&trampoline),
		PTRDIFF(code_data(&trampoline_exit), code_data(&trampoline))
	);
	// copy syscall trampolines
	memcpy(
		payload + sc_offset,
		region_sc_code.start,
		REGION_LENGTH(region_sc_code)
	);
	DBG("sc_size: %zu", dataLength);
	DBG("sc_base: 0x"LX, sc_base);

	intptr_t rc = -1;
	do {
		if(remote_write(ctx, sc_base, payload, dataLength) != dataLength){
			PERROR("failed to write shellcode");
			break;
		}

		uint8_t *verify = calloc(1, dataLength);
		do {
			if(remote_read(ctx, verify, sc_base, dataLength) != dataLength){
				PERROR("verify: readback failed");
				break;
			}

			if(memcmp(payload, verify, dataLength) != 0){
				ERR("verify: verification failed");
				break;
			}
			rc = 0;
		} while(0);
		free(verify);

	} while(0);
	free(payload);

	if(rc < 0){
		return rc;
	}

	*out_sc_base = sc_base;
	return 0;
}

EZAPI remote_sc_set(struct ezinj_ctx *ctx, uintptr_t sc_base){
	r_current_sc_base = sc_base + sc_offset;
	// set the shellcode entry point
	ctx->entry_insn.remote = sc_base
		+ trampoline_offset
		+ trampoline_entry_label;
	return 0;
}

EZAPI remote_sc_free(struct ezinj_ctx *ctx, int flags, uintptr_t sc_base){
	if((flags & SC_ALLOC_ELFHDR) == SC_ALLOC_ELFHDR){
#ifdef EZ_TARGET_DARWIN
		if(remote_pl_free(ctx, sc_base) != 0){
			ERR("remote_pl_free failed");
			return -1;
		}
#else
		if(remote_write(ctx, sc_base, ctx->saved_sc_data, ctx->saved_sc_size) != ctx->saved_sc_size){
			PERROR("remote_write failed");
			return -1;
		}
#endif
		if(ctx->saved_sc_data != NULL){
			free(ctx->saved_sc_data);
			ctx->saved_sc_data = NULL;
		}
	} else if((flags & SC_ALLOC_MMAP) == SC_ALLOC_MMAP){
		if(CHECK(RSCALL2(ctx, __NR_munmap, sc_base, ctx->saved_sc_size)) != 0){
			ERR("remote munmap failed");
			return -1;
		}
	}
	return 0;
}

#if defined(EZ_TARGET_LINUX)
static inline uintptr_t _get_wrapper_target(struct injcode_call *call){
	/**
	 * glibc 2.x on ARM OABI exposes a syscall(2) that only accepts 3 arguments:
	 *  a1: syscall number
	 *  a2: syscall arg1
	 *  a3: syscall arg2
	 *
	 * this means we can only do syscalls with 2 arguments, which is insufficient for
	 *  open(2), read(2) and mmap(2)
	 * which we need to perform the injection
	 * we must therefore intercept these and use the respective libc functions
	 */
	if(call->argc > 0){
		switch(call->argv[0]){
			case __NR_mmap2:
				DBGPTR(call->libc_mmap);
				if(call->libc_mmap != NULL){
					return r_current_sc_base + sc_mmap_offset;
				}
				break;
			#if defined(__NR_open)
			case __NR_open:
			#elif defined(__NR_openat)
			case __NR_openat:
			#endif
				DBGPTR(call->libc_open);
				if(call->libc_open != NULL){
					return r_current_sc_base + sc_open_offset;
				}
				break;
			case __NR_read:
				DBGPTR(call->libc_read);
				if(call->libc_read != NULL){
					return r_current_sc_base + sc_read_offset;
				}
				break;
		}
	}

	return r_current_sc_base + sc_fn_offset;
}
#elif defined(EZ_TARGET_WINDOWS)
static inline uintptr_t _get_wrapper_target(struct injcode_call *call){
	if(call->argc > 0){
		switch(call->argv[0]){
			case __NR_mmap:
				return r_current_sc_base + sc_virtualalloc_offset;
			case __NR_munmap:
				return r_current_sc_base + sc_virtualfree_offset;
			default:
				ERR("Unknown win32 syscall %"PRIuPTR, call->argv[0]);
				break;
		}
	} else {
		ERR("unsupported call");
		return -1;
	}

	return 0;
}
#elif defined(EZ_TARGET_WINDOWS)
static inline uintptr_t _get_wrapper_target(struct injcode_call *call){
	if(call->argc > 0){
		switch(call->argv[0]){
			case __NR_mmap:
				return r_current_sc_base + sc_virtualalloc_offset;
			case __NR_munmap:
				return r_current_sc_base + sc_virtualfree_offset;
			default:
				ERR("Unknown win32 syscall %u", call->argv[0]);
				break;
		}
	} else {
		ERR("unsupported call");
		return -1;
	}

	return 0;
}
#else
static inline uintptr_t _get_wrapper_target(struct injcode_call *call){
	return r_current_sc_base + sc_fn_offset;
}
#endif

#ifdef HAVE_SYSCALLS
EZAPI remote_call_prepare(struct ezinj_ctx *ctx, struct injcode_call *call){
	UNUSED(ctx);

	// tell the wrapper which syscall trampoline to call
	call->wrapper.target = (void *)_get_wrapper_target(call);
	DBGPTR(call->wrapper.target);

	// tell the trampoline to call injected_sc_wrapper
	call->trampoline.fn_addr = r_current_sc_base + sc_wrapper_offset;
	DBGPTR(call->trampoline.fn_addr);
	return 0;
}
#endif
