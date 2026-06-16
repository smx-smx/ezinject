/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <inttypes.h>
#include <ctype.h>

#include "config.h"

#include <fcntl.h>
#include <sched.h>

#ifdef EZ_TARGET_POSIX
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#endif

#include <sys/stat.h>

#include "dlfcn_compat.h"
#include "ezinject_util.h"
#include "ezinject.h"
#include "ezinject_common.h"
#include "ezinject_arch.h"
#include "ezinject_injcode.h"

#include "os/builder.h"

#include "log.h"

static struct ezinj_ctx ctx; // only to be used for sigint handler

ez_region region_pl_code = {
	.start = (void *)&__start_payload,
	.end = (void *)&__stop_payload
};

#ifdef HAVE_SYSCALLS
uintptr_t get_wrapper_address(struct ezinj_ctx *ctx);
#endif

size_t create_layout(struct ezinj_ctx *ctx, size_t dyn_total_size, struct ezinj_pl *layout);

/**
 * Prepares the target process for a call invocation with syscall convention
 * NOTE: this function can be used to call anything, not just system calls
 *
 * @param[in]  orig_ctx	 the current process context
 * @param[out] new_ctx   the new process context
 * @param[in]  call      call arguments and options
 **/
intptr_t setregs_syscall(
	struct ezinj_ctx *ctx,
	regs_t *orig_ctx,
	regs_t *new_ctx,
	struct call_req *call
){
	REG(*new_ctx, REG_PC) = call->insn_addr;

	// this will be passed on the stack
	struct injcode_call *rcall = &call->rcall;
	rcall->magic = EZSC1;

	uintptr_t target_sp = 0;
	if(call->stack_addr != 0){
		target_sp = call->stack_addr;
	} else {
		target_sp = REG(*orig_ctx, REG_SP);
	}
	// allocate remote call on the stack
	uintptr_t r_call_args = target_sp;
	#if STACK_DIR == -1
		// allocate stack data for rcall (see diagram below)
		// this is also used as the remote memcpy base
		r_call_args -= sizeof(*rcall);
	#endif

	rcall->argc = 0;
	rcall->result = 0;
	// copy call arguments
	memcpy(&rcall->argv, &call->argv, sizeof(call->argv));

	os_rcall_setup(ctx, rcall, r_call_args);

#define PLAPI_USE(fn) do { \
	rcall->plapi.fn.fptr = (void *)ctx->plapi.fn; \
	rcall->plapi.fn.got = 0; \
	rcall->plapi.fn.self = (void *)r_call_args + offsetof(struct injcode_call, plapi.fn); \
} while(0)

	PLAPI_USE(inj_memset);
	PLAPI_USE(inj_puts);
	PLAPI_USE(inj_dchar);
	PLAPI_USE(inj_dbgptr);
	PLAPI_USE(inj_fetchsym);
#undef PLAPI_USE

	// set the call structure as argument for the function being called
	rcall->para.trampoline.fn_arg = r_call_args;

	// count syscall arguments excluding syscall number
	for(int i=1; i<SC_MAX_ARGS; i++){
		if(CALL_HAS_ARG(*call, i)){
			rcall->argc++;
		}
	}

	#ifdef HAVE_SYSCALLS
	/**
	 * this target supports true system calls
	 * use a wrapper in-between to avoid stack corruption
	 * in some scenarios
	 *
	 * trampoline -> wrapper -> syscall
	 **/
	rcall->para.trampoline.fn_addr = get_wrapper_address(ctx);
#ifdef EZ_ARCH_HPPA
	rcall->para.trampoline.fn_self = r_call_args + offsetof(struct injcode_call, para.trampoline.fn_addr);
	rcall->wrapper.target.self = (void *)(r_call_args + offsetof(struct injcode_call, wrapper));
#endif
	DBGPTR(rcall->para.trampoline.fn_addr);
	if(call->syscall_mode){
		/**
		 * set the branch target
		 * (based on the number of syscall arguments)
		 **/
		if(remote_call_prepare(ctx, rcall) < 0){
			ERR("remote_call_prepare failed");
			return -1;
		}
	} else {
		// call the user supplied target through the wrapper
		rcall->wrapper.target.fptr = (intptr_t (*)(volatile struct injcode_call *))ctx->branch_target.remote;
	}
	#else
	/**
	 * call wrapper on PL,
	 * which will copy `injcode_call` to `injcode_bearing` on Darwin
	 **/
	rcall->para.trampoline.fn_addr = ctx->wrapper_address.remote;

	// call the user supplied target through the wrapper
	rcall->wrapper.target.fptr = (intptr_t (*)(volatile struct injcode_call *))ctx->branch_target.remote;
	#endif

	if(ctx->rcall_handler_pre != NULL){
		if(ctx->rcall_handler_pre(ctx, &call->rcall) < 0){
			ERR("rcall_handler_pre failed");
			return -1;
		}
	}

	// backup the stack area being overwritten
	ssize_t backupSize = (ssize_t)WORDALIGN(sizeof(*rcall));
	uint8_t *saved_stack = calloc(backupSize, 1);
	if(remote_read(ctx, saved_stack, r_call_args, backupSize) != backupSize){
		ERR("failed to backup stack");
		free(saved_stack);
		return -1;
	}

	// write the remote call onto the stack
	if(remote_write(
		ctx,
		r_call_args,
		rcall, sizeof(*rcall)
	) != sizeof(*rcall)){
		ERR("failed to write remote call");
		free(saved_stack);
		return -1;
	}

	// save original info for later
	call->backup_addr = r_call_args;
	call->backup_data = saved_stack;
	call->backup_size = backupSize;

	#if STACK_DIR == -1
	/**
	 * if the stack grows down, we must decrement by the amount of data we want
	 * to consume.
	 * refer to the following diagram (with dummy sample address)
	 *
	 * 0x0 -------- <-- r_call_args (memcpy base)
	 * 0x1 | call |
	 * 0x2 |----- | <-- New Sp Top
	 * 0x3 | para |
	 * 0x4 -------- <-- SP Top
	 *
	 * POP *increments* the stack towards SP Top
	 */
	REG(*new_ctx, REG_SP) = target_sp - sizeof(struct injcode_trampoline);
	#elif STACK_DIR == 1
	/**
	 * if the stack grows up, we must increment by the amount of data copied.
	 * this is because the stack grows up, so further calls performed
	 * within the payload will overwrite the injcode_call on the stack
	 * refer to the following diagram (with dummy sample address)
	 *
	 * to avoid trashing stack out of bounds, we leave entry_stack
	 * at the end, and backtrack by that amount
	 *
	 * 0x0 -------- <-- r_call_args (memcpy base)
	 * 0x1 | call |
	 * 0x2 |----- | <-- SP Top
	 * 0x3 | para |
	 * 0x4 |----- | <-- New Sp top
	 * 0x5 |  stk |
	 * 0x6 --------
	 *
	 * POP *decrements* the stack towards SP Top
	 */
	REG(*new_ctx, REG_SP) = target_sp + sizeof(*rcall)
		- sizeof(rcall->para.entry_stack);
	#endif

#ifdef DEBUG
	DBGPTR((void *)REG(*new_ctx, REG_SP));
#endif

#if defined(EZ_ARCH_ARM) && defined(HAVE_PSR_T_BIT)
	// set the ARM/Thumb flag for the shellcode invocation
	#ifdef USE_ARM_THUMB
	REG(*new_ctx, ARM_cpsr) = REG(*new_ctx, ARM_cpsr) | PSR_T_BIT;
	#else
	REG(*new_ctx, ARM_cpsr) = REG(*new_ctx, ARM_cpsr) & ~PSR_T_BIT;
	#endif
#endif

	return 0;
}


intptr_t remote_call_setup(struct ezinj_ctx *ctx, struct call_req *call, regs_t *orig_ctx, regs_t *new_ctx){
	memset(orig_ctx, 0x00, sizeof(*orig_ctx));

	if(remote_getregs(ctx, orig_ctx) < 0){
		PERROR("remote_getregs failed (initial)");
		return -1;
	}
	memcpy(new_ctx, orig_ctx, sizeof(*orig_ctx));

	if(setregs_syscall(ctx, orig_ctx, new_ctx, call) < 0){
		ERR("setregs_syscall failed");
		return -1;
	}

	if(remote_use_remoting(ctx)){
		if(remote_start_thread(ctx, new_ctx) < 0){
			PERROR("remote_setregs failed");
			return -1;
		}
	} else if(remote_setregs(ctx, new_ctx) < 0){
		PERROR("remote_setregs failed");
		return -1;
	}

	return 0;
}

intptr_t remote_call_common(struct ezinj_ctx *ctx, struct call_req *call){
	regs_t orig_ctx, new_ctx;
	if(remote_call_setup(ctx, call, &orig_ctx, &new_ctx) < 0){
		ERR("remote_call_setup failed");
		return -1;
	}

	if(ctx->pl_debug) {
		if(remote_detach(ctx) != 0){
			PERROR("ptrace");
			return -1;
		}
	} else if(remote_continue(ctx, 0) != 0){
		PERROR("ptrace");
		return -1;
	}

	bool wait = false;
	do {
		os_invoke_begin(ctx, &call->rcall);

		if(ctx->bail){
			// hard exit for debugging purposes
			// (debugging crashes in target)
			exit(0);
		}

		intptr_t status = remote_wait(ctx, 0);
		if(status < 0){
			ERR("remote_wait failed");
			return -1;
		}

		wait = os_forward_signal(ctx, status, call->syscall_mode);
	} while(wait);

	if(ctx->pl_debug){
		return -1;
	}


	if(ctx->rcall_handler_post != NULL){
		if(ctx->rcall_handler_post(ctx, &call->rcall) < 0){
			ERR("rcall_handler_post failed");
			return -1;
		}
	}

	// read the rcall result from the stack
	remote_read(ctx,
		&call->rcall.result,
		RCALL_FIELD_ADDR(&call->rcall, result),
		sizeof(uintptr_t)
	);

#ifdef DEBUG
	DBG("[RET] = %"PRIdPTR, call->rcall.result);
#endif

	if(!remote_use_remoting(ctx)){
		if(remote_getregs(ctx, &new_ctx) < 0){
			ERR("remote_getregs failed (restore)");
			return -1;
		}

		/**
		 * the payload is expected to use its own stack
		 * so we don't restore stack in that case
		 * because the stack could be unmapped
		 */
		if(call->syscall_mode){
			DBG("restoring stack data");
			if(remote_write(ctx,
				call->backup_addr,
				call->backup_data,
				call->backup_size
			) != call->backup_size){
				ERR("failed to restore saved stack data");
			}
		}

		if(remote_setregs(ctx, &orig_ctx)){
			PERROR("remote_setregs failed");
		}

		#ifdef DEBUG
		DBG("SP: %p", (void *)((uintptr_t)REG(new_ctx, REG_SP)));
		DBG("PC: %p => %p",
			(void *)call->insn_addr,
			(void *)((uintptr_t)REG(new_ctx, REG_PC)));
		#endif
	}

	return call->rcall.result;
}

intptr_t remote_call(
	struct ezinj_ctx *ctx,
	unsigned int argmask, ...
){
	struct call_req call = {
		.insn_addr = ctx->entry_insn.remote,
		.stack_addr = ctx->pl_stack.remote,
		.syscall_mode = ctx->syscall_mode,
		.argmask = argmask,
		.backup_data = NULL,
		.backup_size = 0,
		.backup_addr = 0
	};
	DBG("=====================");

	va_list ap;
	va_start(ap, argmask);

	for(int i=0; i<CALL_MAX_ARGS; i++){
		call.argv[i] = (CALL_HAS_ARG(call, i)) ? va_arg(ap, uintptr_t) : 0;
	}

	intptr_t rc = remote_call_common(ctx, &call);
	if(call.backup_addr){
		free(call.backup_data);
	}
	return rc;
}

struct ezinj_str ezstr_new(enum ezinj_str_id id, const char *str, size_t *pSize){
	if(!str){
		str = "";
	}

	struct ezinj_str bstr = {
		.id = (enum ezinj_str_id)id,
		.str = str
	};
	/**
	 * align the size of the string entry
	 * since some architectures (e.g. ARMv4)
	 * don't like doing unaligned accesses
	 * and will corrupt memory
	 */
	*pSize = (size_t)WORDALIGN(STRSZ(str));
	return bstr;
}

/**
 * @brief default implementation of libc lookup
 *
 * @param ctx
 */
static int libc_init_default(struct ezinj_ctx *ctx){
	const char *ignores[] = {"ld-", NULL};

	/**
	 * $FIXME: this code does not belong here.
	 * it should be refactored together with `libc_init_default`
	 */
#ifdef EZ_TARGET_WINDOWS
	OSVERSIONINFO osvi = {
		.dwOSVersionInfoSize = sizeof(osvi)
	};
	if(!GetVersionEx(&osvi)) {
		PERROR("GetVersionEx");
		return 1;
	}
	if(osvi.dwPlatformId != VER_PLATFORM_WIN32_NT){
		// win32, stop here
		return 0;
	}
#endif

	INFO("Looking up %s", ctx->libc_name);

	void *h_libc = LIB_OPEN(ctx->libc_name);
	if(!h_libc){
		ERR("dlopen(%s) failed: %s", ctx->libc_name, LIB_ERROR());
		return 1;
	}

	#ifdef EZ_TARGET_LINUX
	#define LIBC_SEARCH "libc"
	#else
	#define LIBC_SEARCH ctx->libc_name
	#endif

	ez_addr libc = {
		.local  = (uintptr_t) get_base(ctx, getpid(), LIBC_SEARCH, ignores),
		.remote = (uintptr_t) get_base(ctx, ctx->target, LIBC_SEARCH, ignores)
	};

	#undef LIBC_SEARCH

	DBGPTR(libc.remote);
	DBGPTR(libc.local);

	if(!libc.local || !libc.remote) {
		ERR("Failed to get libc base");
		return 1;
	}
	ctx->libc = libc;

#if !defined(HAVE_LIBDL_IN_LIBC)
	{
		void *h_libdl = LIB_OPEN(ctx->libdl_name);
		if(!h_libdl){
			ERR("dlopen(%s) failed: %s", ctx->libdl_name, LIB_ERROR());
			return 1;
		}

		/**
		 * $FIXME:
		 * this is platform dependent and is left here as a default. it should be moved to the posix target
		 * this code will try to lookup dlopen/dlsym from libdl (the most common scenario)
		 * there are some platforms where this doesn't work (e.g. Windows), but this lookup isn't fatal
		 **/

		ez_addr libdl = {
			.local = (uintptr_t)get_base(ctx, getpid(), "libdl", NULL),
			.remote = (uintptr_t)get_base(ctx, ctx->target, "libdl", NULL)
		};
		ctx->libdl = libdl;

		void *dlopen_local = LIB_GETSYM(h_libdl, "dlopen");
		off_t dlopen_offset = (off_t)PTRDIFF(dlopen_local, libdl.local);
		ctx->dlopen_offset = dlopen_offset;

		void *dlclose_local = LIB_GETSYM(h_libdl, "dlclose");
		off_t dlclose_offset = (off_t)PTRDIFF(dlclose_local, libdl.local);
		ctx->dlclose_offset = dlclose_offset;

		void *dlsym_local = LIB_GETSYM(h_libdl, "dlsym");
		off_t dlsym_offset = (off_t)PTRDIFF(dlsym_local, libdl.local);
		ctx->dlsym_offset = dlsym_offset;

		LIB_CLOSE(h_libdl);
	}
#endif

	#ifdef EZ_TARGET_POSIX
	uintptr_t libc_got = UPTR(code_data(&syscall, CODE_DATA_DPTR));
		ctx->libc_got = (ez_addr){
		.local = libc_got,
		.remote = EZ_REMOTE(ctx->libc, libc_got)
	};
	#endif

	ctx->libc_syscall = sym_addr(h_libc, "syscall", ctx->libc);
	DBGPTR(ctx->libc_syscall.local);
	DBGPTR(ctx->libc_syscall.remote);

	LIB_CLOSE(h_libc);
	return 0;
}

int libc_init(struct ezinj_ctx *ctx){
	os_plt_resolve();

	if(libc_init_default(ctx) != 0){
		return 1;
	}

	if(resolve_libc_symbols(ctx) != 0){
		return 1;
	}

	return 0;
}

int push_string(
	struct ezinj_strings *strings,
	enum ezinj_str_id str_id,
	const char *str
){
	unsigned index = MAX(str_id, strings->num_strings);
	if(index >= strings->argsLim){
		// insert index + 128 new items
		strings->argsLim = index + 128;
		strings->args = realloc(strings->args, sizeof(struct ezinj_str) * strings->argsLim);
		if(strings->args == NULL){
			PERROR("realloc");
			return -1;
		}
	}
	size_t str_size = 0;
	strings->args[str_id] = ezstr_new(str_id, str, &str_size);
	strings->dyn_str_size += str_size;
	return 0;
}

struct injcode_bearing *prepare_bearing(struct ezinj_ctx *ctx, int argc, char *argv[]){
	struct ezinj_strings strings = {
		.dyn_str_size = 0,
		.num_strings = EZSTR_MAX_DEFAULT,
		.args = NULL,
		.argsLim = 0
	};

	{
		unsigned argsLim = 128;
		struct ezinj_str *args = calloc(argsLim, sizeof(struct ezinj_str));
		if(!args){
			PERROR("calloc");
			return NULL;
		}
		strings.args = args;
		strings.argsLim = argsLim;
	}

	intptr_t rc = -1;
#define PUSH_STRING(id, str) \
	if((rc=push_string(&strings, id, str)) < 0) goto end;

	struct os_builder_ctx os_ctx;
	os_strings_init(ctx, &strings, &os_ctx);

	// library to load
	char *libName = os_realpath(argv[0]);
	if(!libName){
		ERR("realpath(%s) failed", argv[0]);
		return NULL;
	}

	// libdl.so name (without path)
	PUSH_STRING(EZSTR_API_LIBDL, ctx->libdl_name);
	// libpthread.so name (without path)
	PUSH_STRING(EZSTR_API_LIBPTHREAD, ctx->libpthread_name);

	char *logPath = NULL;

	if(ctx->module_logfile && strlen(ctx->module_logfile) > 0){
		// make sure the log file exists before we call realpath on it
		FILE *fh = fopen(ctx->module_logfile, "a");
		if(!fh){
			ERR("fopen \"%s\" failed", ctx->module_logfile);
			return NULL;
		}
		fclose(fh);

		logPath = os_realpath(ctx->module_logfile);
		if(!logPath){
			ERR("realpath(%s) failed", ctx->module_logfile);
			return NULL;
		}

		PUSH_STRING(EZSTR_LOG_FILEPATH, logPath);
	} else {
		PUSH_STRING(EZSTR_LOG_FILEPATH, "");
	}

	PUSH_STRING(EZSTR_API_CRT_INIT, "crt_init");

	// argv0
	PUSH_STRING(EZSTR_ARGV0, libName);

	// user arguments
	for(int i=1; i < argc; i++){
		PUSH_STRING(EZSTR_ARGV0+i, argv[i]);
		++strings.num_strings;
	}


#undef PUSH_STRING

	size_t dyn_ptr_size = argc * sizeof(char *);
	size_t dyn_entries_size = strings.num_strings * sizeof(struct ezinj_str);
	size_t dyn_total_size = dyn_ptr_size + dyn_entries_size + strings.dyn_str_size;
	size_t mapping_size = create_layout(ctx, dyn_total_size, &ctx->pl);
	if(mapping_size == 0){
		ERR("create_layout failed");
		return NULL;
	}

	struct injcode_bearing *br = (struct injcode_bearing *)ctx->mapped_mem.local;
	if(!br){
		PERROR("malloc");
		goto end;
	}

	memset(br, 0x00, sizeof(*br));
	br->magic = EZBR1;
	br->mapping_size = mapping_size;
	br->pl_debug = ctx->pl_debug;
	br->libdl_handle = (void *)ctx->libdl.remote;

	os_bearing_setup(br, ctx, &os_ctx);

	br->dlopen_offset = ctx->dlopen_offset;
	br->dlclose_offset = ctx->dlclose_offset;
	br->dlsym_offset = ctx->dlsym_offset;

#undef USE_LIBC_SYM

	// normally false, but can be optionally forced to true
	// by passing -r to ezinject
	// whether it will be respected or not depends on the module implementation
	br->user.persist = ctx->module_persist;

	br->argc = argc;
	br->dyn_total_size = dyn_total_size;
	br->num_strings = strings.num_strings;

	char *stringEntries = (char *)br + sizeof(*br) + dyn_ptr_size;
	char *stringData = stringEntries + dyn_entries_size;

	struct ezinj_str *pEntries = (struct ezinj_str *)stringEntries;
	size_t strtbl_off = 0;
	for(unsigned i=0; i<strings.num_strings; i++){
		pEntries->id = strings.args[i].id;
		// store the current string offset. it will rebased by injcode
		pEntries->str = (char *)strtbl_off;
		++pEntries;

		if(!strings.args[i].str){
			continue;
		}
		size_t str_sz = STRSZ(strings.args[i].str);
		memcpy(stringData, strings.args[i].str, str_sz);
		stringData += str_sz;
		strtbl_off += str_sz;
	}


end:
	free(os_ctx.pl_filename);

	if(libName){
		free(libName);
	}
	if(logPath){
		free(logPath);
	}

	// copy code
	memcpy(ctx->pl.code_start, region_pl_code.start, REGION_LENGTH(region_pl_code));
	if(strings.args){
		free(strings.args);
	}
	return br;
}

size_t create_layout(struct ezinj_ctx *ctx, size_t dyn_total_size, struct ezinj_pl *layout){
	// br + argv
	size_t br_size = (size_t)WORDALIGN(sizeof(struct injcode_bearing) + dyn_total_size);
	// size of code payload
	size_t code_size = (size_t)WORDALIGN(REGION_LENGTH(region_pl_code));

	size_t stack_offset = br_size + code_size;
	size_t mapping_size = stack_offset + PL_STACK_SIZE;
	mapping_size = (size_t)ALIGN(mapping_size, ctx->pagesize);

	DBG("br_size=%zu", br_size);
	DBG("code_size=%zu", code_size);
	DBG("stack_offset=%zu", stack_offset);
	DBG("mapping_size=%zu", mapping_size);

	void *mapped_mem = calloc(1, mapping_size);
	if(!mapped_mem){
		PERROR("calloc");
		return 0;
	}

	ctx->mapped_mem.local = (uintptr_t)mapped_mem;

	/** prepare payload layout **/

	uint8_t *pMem = (uint8_t *)ctx->mapped_mem.local;
	layout->br_start = pMem;
	pMem += br_size;

	layout->code_start = pMem;

	// stack is located at the end of the memory map
	layout->stack_top = (uint8_t *)ctx->mapped_mem.local + mapping_size;
	#if STACK_DIR == 1
	layout->stack_top -= PL_STACK_SIZE;
	#endif

	/** align stack **/

	#if defined(EZ_ARCH_AMD64) || defined(EZ_ARCH_ARM64) || defined(EZ_ARCH_PPC64)
	// x64 requires a 16 bytes aligned stack for movaps
	// force stack to snap to the lowest 16 bytes, or it will crash on x64
	layout->stack_top = (uint8_t *)((uintptr_t)layout->stack_top & ~ALIGNMSK(16));
	#else
	layout->stack_top = (uint8_t *)((uintptr_t)layout->stack_top & ~ALIGNMSK(sizeof(void *)));
	#endif

	return mapping_size;
}

void cleanup_mem(struct ezinj_ctx *ctx){
	free((void *)ctx->mapped_mem.local);
}

void sigint_handler(int signum){
	UNUSED(signum);
	cleanup_mem(&ctx);
}

static void ezinject_log_init(){
	log_config_t log = {
		.log_leave_open = 1,
		.log_output = stdout,
		.verbosity = V_INFO
	};
	log_init(&log);
}

int ezinject_main(
	struct ezinj_ctx *ctx,
	int argc, char *argv[]
){
	os_print_maps();

	signal(SIGINT, sigint_handler);

	// prepare bearing
	struct injcode_bearing *br = prepare_bearing(ctx, argc, argv);
	if(br == NULL){
		return -1;
	}


	uintptr_t r_sc_elf = 0;
	uintptr_t r_sc_vmem = 0;

	// allocate initial shellcode on the ELF header
	if(os_sc_init(ctx, &r_sc_elf) != 0)
		return -1;

	intptr_t err = -1;
	do {
		// creates the new payload area with mmap (invoked from EXEHDR)
		INFO("target: allocating %zu bytes", br->mapping_size);
		uintptr_t remote_shm_ptr = remote_pl_alloc(ctx, br->mapping_size);
		remote_shm_ptr = os_alloc_retry(ctx, remote_shm_ptr, br->mapping_size);

		if(remote_shm_ptr == 0){
			ERR("Remote alloc failed");
			break;
		}
		INFO("target: payload base: %p", (void *)remote_shm_ptr);

		ctx->mapped_mem.remote = remote_shm_ptr;

		struct ezinj_pl *pl = &ctx->pl;

		INFO("target: copying payload");
		if(os_pl_copy(ctx, br->mapping_size) != 0){
			ERR("os_pl_copy failed");
			break;
		}

		if(os_sc_relocate(ctx, r_sc_elf, &r_sc_vmem) < 0)
			return -1;

		// switch to SIGSTOP wait mode
		ctx->syscall_mode = false;

		/**
		 * now that PL is available and mapped, we can use it
		 * for stack and entry point
		 **/

		// switch to stack on PL
		uintptr_t *target_sp = (uintptr_t *)pl->stack_top;
		ctx->pl_stack.remote = (uintptr_t)PL_REMOTE(ctx, target_sp);

		// use trampoline on PL
		ctx->entry_insn.remote = PL_REMOTE_CODE(ctx, code_data(&trampoline_entry, CODE_DATA_DEREF));
		ctx->wrapper_address.remote = PL_REMOTE_CODE(ctx, code_data(&injected_pl_wrapper, CODE_DATA_DEREF));
		// tell the trampoline to call the main injcode
		ctx->branch_target.remote = PL_REMOTE_CODE(ctx, code_data(&injected_fn, CODE_DATA_DEREF));

		// init plapi
		#define PLAPI_SET(ctx, fn) ctx->plapi.fn = PL_REMOTE_CODE(ctx, code_data(&fn, CODE_DATA_DEREF))
		PLAPI_SET(ctx, inj_memset);
		PLAPI_SET(ctx, inj_puts);
		PLAPI_SET(ctx, inj_dchar);
		PLAPI_SET(ctx, inj_dbgptr);
		PLAPI_SET(ctx, inj_fetchsym);
		#undef PLAPI_SET

		// when syscall_mode = false, SC is skipped
		INFO("target: call chain");
		INFO("- trampoline_entry: %p", (void *)ctx->entry_insn.remote);
		// note: transition from trampoline -> branch may go through the wrapper,
		// when HAVE_SYSCALLS
		INFO("- branch_target:    %p", (void *)ctx->branch_target.remote);
		INFO("- injcode_bearing:  %p", PL_REMOTE(ctx, pl->br_start));
		err = CHECK(RSCALL1(ctx, EZBR1, PL_REMOTE(ctx, pl->br_start)));

		/**
		 * if payload debugging is on, skip any cleanup
		 **/
		if(ctx->pl_debug){
			return -1;
		}

		// restore syscall behavior (to call munmap, if needed by the target)
		ctx->syscall_mode = true;
		ctx->pl_stack.remote = 0;
		INFO("target: freeing payload memory");
		//remote_pl_free(ctx, remote_shm_ptr);

		if(os_sc_cleanup_vmem(ctx, &r_sc_elf, r_sc_vmem) < 0)
			return -1;

		// now free the ELF header once more (no syscalls allowed after this point)
		if(remote_sc_free(ctx, SC_ALLOC_ELFHDR, r_sc_elf) != 0){
			ERR("remote_sc_free: ELF header restore failed");
			return -1;
		}
	} while(0);

	return err;
}

int main(int argc, char *argv[]){
	ezinject_log_init();

#ifdef DEBUG
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
#endif

	memset(&ctx, 0x00, sizeof(ctx));

	const char *module_logfile = NULL;

	{
		int c;
		while ((c = getopt (argc, argv, "hdrl:v:")) != -1){
			switch(c){
				case 'd':
					WARN("payload debugging enabled");
					ctx.pl_debug = 1;
					break;
				case 'r':
					ctx.module_persist = true;
					break;
				case 'l':;
					module_logfile = strdup(optarg);
					break;
				case 'v':;
					switch(toupper(*optarg)){
						case 'D':
							log_set_verbosity(V_DBG);
							break;
					}
					break;
				case 'h':
					goto usage;
			}
		}
	}

	if(argc < 3) {
		usage:
		fprintf(stderr,
			"Usage: %s [-h|-d|-r|-l <log_path>|-v <verbosity>] <pid> <library.so> -- [args...]\n"
			"  -r: resident/persistent user module (won't be unloaded). NOTE: may still be overridden by the loaded module\n"
			"  -l <log path>: specify log file for payload/module log messages\n"
			"  -d: payload debug mode (skips thread wait/cleanup)\n", argv[0]
		);
		return 1;
	}

	const char *argPid = argv[optind++];
	ctx.target = strtoul(argPid, NULL, 10);
	ctx.module_logfile = (char *)module_logfile;

	#ifdef DYN_LINKER_NAME
	ctx.ldso_name = DYN_LINKER_NAME;
	#endif
	ctx.libc_name = C_LIBRARY_NAME;
	ctx.libdl_name = DL_LIBRARY_NAME;
	ctx.libpthread_name = PTHREAD_LIBRARY_NAME;

	os_pagesize_init(&ctx);

	if(os_api_init(&ctx) != 0){
		ERR("os_api_init() failed");
		return 1;
	}

	INFO("Attaching to %"PRIuMAX, (uintmax_t)ctx.target);

	if(remote_attach(&ctx) < 0){
		PERROR("remote_attach failed");
		return 1;
	}

	if(libc_init(&ctx) != 0){
		ERR("libc_init() failed");
		return 1;
	}
	ctx.r_xpage_base = (uintptr_t)get_base(&ctx, ctx.target, NULL, NULL);

	INFO("waiting for target to stop...");

	int err = 0;
	if(os_post_attach_wait(&ctx) < 0){
		ERR("remote_wait");
		return 1;
	}

	err = ezinject_main(&ctx, argc - optind, &argv[optind]);
	if(os_should_retry(&ctx, err)){
		cleanup_mem(&ctx);
		if(libc_init(&ctx) != 0){
			return 1;
		}
		err = ezinject_main(&ctx, argc - optind, &argv[optind]);
	}


	INFO("detaching...");
	if(remote_detach(&ctx) < 0){
		PERROR("remote_detach failed");
	}

	/**
	 * skip IPC cleanup if we encountered any error
	 * (payload debugging counts as failure)
	 **/
	if(err != 0){
		if(ctx.pl_debug){
			INFO("You may now attach with gdb for payload debugging");
			INFO("Press Enter to quit");
			getchar();
		}
	}

	cleanup_mem(&ctx);
	return (err == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
