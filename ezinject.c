#define _GNU_SOURCE
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

#include "config.h"

#include <fcntl.h>
#include <dlfcn.h>
#include <sched.h>


#ifdef HAVE_SYS_SHM_H
#include <sys/shm.h>
#endif

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

#if defined(EZ_TARGET_LINUX) && !defined(HAVE_SHM_SYSCALLS)
#include <asm-generic/ipc.h>
#endif

#include "ezinject_util.h"
#include "ezinject.h"
#include "ezinject_compat.h"
#include "ezinject_common.h"
#include "ezinject_arch.h"
#include "ezinject_injcode.h"

enum verbosity_level verbosity = V_DBG;

static struct ezinj_ctx ctx; // only to be used for sigint handler

static ez_region region_pl_code = {
	.start = (void *)&__start_payload,
	.end = (void *)&__stop_payload
};

static ez_region region_sc_code = {
	.start = (void *)&__start_syscall,
	.end = (void *)&__stop_syscall
};

static void *code_data(void *code){
#if defined(EZ_ARCH_ARM) && defined(USE_ARM_THUMB)
	return (void *)(UPTR(code) & ~1);
#else
	return code;
#endif
}

/**
 * Get the address of the call wrapper
 **/
uintptr_t get_wrapper_address(struct ezinj_ctx *ctx){
	uintptr_t codeBase = (uintptr_t) get_base(ctx->target, NULL, NULL);
	if(codeBase == 0){
		ERR("Could not obtain code base");
		return 0;
	}
	DBGPTR(codeBase);

	off_t trampoline_offset = 0;
	size_t trampoline_size = ROUND_UP(
		PTRDIFF(code_data(&trampoline_exit), code_data(&trampoline)),
		sizeof(uintptr_t)
	);

	off_t sc_offset = trampoline_offset + trampoline_size;
	uintptr_t r_sc_base = codeBase + sc_offset;

	uintptr_t sc_wrapper_offset = PTRDIFF(&injected_sc_wrapper, region_sc_code.start);
	return r_sc_base + sc_wrapper_offset;
}

int allocate_shm(struct ezinj_ctx *ctx, size_t dyn_total_size, struct ezinj_pl *layout, size_t *allocated_size);
int resolve_libc_symbols(struct ezinj_ctx *ctx);

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

	struct injcode_call *rcall = &call->rcall;
	
	uintptr_t target_sp = 0;
	if(call->stack_addr != 0){
		target_sp = call->stack_addr;
	} else {
		target_sp = REG(*orig_ctx, REG_SP);
	}
	uintptr_t r_call_args = target_sp - sizeof(*rcall);

	rcall->argc = 0;
	rcall->result = 0;
	memcpy(&rcall->argv, &call->argv, sizeof(call->argv));

#ifdef EZ_TARGET_POSIX
	rcall->libc_syscall = (void *)ctx->libc_syscall.remote;
#endif

	// skip syscall nr
	for(int i=1; i<SC_MAX_ARGS; i++){
		if(CALL_HAS_ARG(*call, i)){
			rcall->argc++;
		}
	}

	/**
	 * set trampoline params
	 **/
	rcall->trampoline.fn_arg = r_call_args;

	#if defined(EZ_TARGET_POSIX) && !defined(EZ_TARGET_DARWIN)
	rcall->trampoline.fn_addr = get_wrapper_address(ctx);
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
		// set the user supplied branch target
		rcall->wrapper.target = ctx->branch_target.remote;
	}
	#else
	rcall->trampoline.fn_addr = ctx->branch_target.remote;
	#endif

	if(ctx->rcall_handler_pre != NULL){
		if(ctx->rcall_handler_pre(ctx, &call->rcall) < 0){
			ERR("rcall_handler_pre failed");
			return -1;
		}
	}

	size_t backupSize = ROUND_UP(sizeof(*rcall), sizeof(uintptr_t));
	
	uint8_t *saved_stack = calloc(backupSize, 1);
	if(remote_read(ctx, saved_stack, r_call_args, backupSize) != backupSize){
		ERR("failed to backup stack");
		free(saved_stack);
		return -1;
	}

	if(remote_write(
		ctx,
		r_call_args,
		rcall, sizeof(*rcall)
	) != sizeof(*rcall)){
		ERR("failed to write remote call");
		free(saved_stack);
		return -1;
	}

	call->backup_addr = r_call_args;
	call->backup_data = saved_stack;
	call->backup_size = backupSize;

	REG(*new_ctx, REG_SP) = target_sp - sizeof(struct injcode_trampoline);
	DBGPTR((void *)REG(*new_ctx, REG_SP));

#ifdef EZ_ARCH_ARM
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
		PERROR("remote_getregs failed");
		return -1;
	}
	memcpy(new_ctx, orig_ctx, sizeof(*orig_ctx));

	if(setregs_syscall(ctx, orig_ctx, new_ctx, call) < 0){
		ERR("setregs_syscall failed");
		return -1;
	}
	if(remote_setregs(ctx, new_ctx) < 0){
		PERROR("remote_setregs failed");
		return -1;
	}

	return 0;
}

uintptr_t remote_call_common(struct ezinj_ctx *ctx, struct call_req *call){
	regs_t orig_ctx, new_ctx;
	if(remote_call_setup(ctx, call, &orig_ctx, &new_ctx) < 0){
		ERR("remote_call_setup failed");
		return -1;
	}

	if(remote_continue(ctx, 0) < 0){
		PERROR("ptrace");
		return -1;
	}

	if(remote_wait(ctx, 0) < 0){
		ERR("remote_wait failed");
		return -1;
	}

	if(call->syscall_mode == 0 && ctx->pl_debug){
		return -1;
	}


	if(ctx->rcall_handler_post != NULL){
		if(ctx->rcall_handler_post(ctx, &call->rcall) < 0){
			ERR("rcall_handler_post failed");
			return -1;
		}
	}

	remote_read(ctx,
		&call->rcall.result,
		RCALL_FIELD_ADDR(&call->rcall, result),
		sizeof(uintptr_t)
	);

	DBG("[RET] = %"PRIdPTR, call->rcall.result);

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
	DBG("PC: %p => %p",
		(void *)call->insn_addr,
		(void *)((uintptr_t)REG(new_ctx, REG_PC)));
#endif

	return call->rcall.result;
}

uintptr_t remote_call(
	struct ezinj_ctx *ctx,
	unsigned int argmask, ...
){
	struct call_req call = {
		.insn_addr = ctx->trampoline_insn.remote,
		.stack_addr = ctx->pl_stack.remote,
		.syscall_mode = ctx->syscall_mode,
		.argmask = argmask
	};

	va_list ap;
	va_start(ap, argmask);

	for(int i=0; i<CALL_MAX_ARGS; i++){
		call.argv[i] = (CALL_HAS_ARG(call, i)) ? va_arg(ap, uintptr_t) : 0;
	}

	return remote_call_common(ctx, &call);
}

struct ezinj_str ezstr_new(char *str){
	struct ezinj_str bstr = {
		.len = STRSZ(str),
		.str = str
	};
	return bstr;
}

ez_addr sym_addr(void *handle, const char *sym_name, ez_addr lib){
	uintptr_t sym_addr = (uintptr_t)dlsym(handle, sym_name);
	ez_addr sym = {
		.local = sym_addr,
		.remote = (sym_addr == 0) ? 0 : EZ_REMOTE(lib, sym_addr)
	};
	return sym;
}

#ifdef EZ_TARGET_LINUX
#define LIBC_SEARCH "libc"
#else
#define LIBC_SEARCH C_LIBRARY_NAME
#endif

int libc_init(struct ezinj_ctx *ctx){
	char *ignores[] = {"ld-", NULL};

	INFO("Looking up " C_LIBRARY_NAME);
	ez_addr libc = {
		.local  = (uintptr_t) get_base(getpid(), LIBC_SEARCH, ignores),
		.remote = (uintptr_t) get_base(ctx->target, LIBC_SEARCH, ignores)
	};

	DBGPTR(libc.remote);
	DBGPTR(libc.local);

	if(!libc.local || !libc.remote) {
		ERR("Failed to get libc base");
		return 1;
	}
	ctx->libc = libc;

	void *h_libc = dlopen(C_LIBRARY_NAME, RTLD_LAZY);
	if(!h_libc){
		ERR("dlopen("C_LIBRARY_NAME") failed: %s", dlerror());
		return 1;
	}

	{
		void *h_libdl = dlopen(DL_LIBRARY_NAME, RTLD_LAZY);
		if(!h_libdl){
			ERR("dlopen("DL_LIBRARY_NAME") failed: %s", dlerror());
			return 1;
		}

		ez_addr libdl = {
			.local = (uintptr_t)get_base(getpid(), "libdl", NULL),
			.remote = (uintptr_t)get_base(ctx->target, "libdl", NULL)
		};
		ctx->libdl = libdl;

		DBGPTR(libdl.local);
		DBGPTR(libdl.remote);

		void *dlopen_local = dlsym(h_libdl, "dlopen");
		off_t dlopen_offset = (off_t)PTRDIFF(dlopen_local, libdl.local);
		DBG("dlopen offset: 0x%lx", dlopen_offset);
		ctx->dlopen_offset = dlopen_offset;

		void *dlclose_local = dlsym(h_libdl, "dlclose");
		off_t dlclose_offset = (off_t)PTRDIFF(dlclose_local, libdl.local);
		DBG("dlclose offset: 0x%lx", dlclose_offset);
		ctx->dlclose_offset = dlclose_offset;

		void *dlsym_local = dlsym(h_libdl, "dlsym");
		off_t dlsym_offset = (off_t)PTRDIFF(dlsym_local, libdl.local);
		DBG("dlsym offset: 0x%lx", dlsym_offset);
		ctx->dlsym_offset = dlsym_offset;

		dlclose(h_libdl);
	}

	if(resolve_libc_symbols(ctx) != 0){
		return 1;
	}

#define USE_LIBC_SYM(name) do { \
	ctx->libc_##name = sym_addr(h_libc, #name, libc); \
	DBGPTR(ctx->libc_##name.local); \
	DBGPTR(ctx->libc_##name.remote); \
} while(0)

	USE_LIBC_SYM(syscall);
#undef USE_LIBC_SYM

	dlclose(h_libc);
	return 0;
}

/**
 * Marshals the string @str into @strData, advancing the data pointer as needed
 * 
 * @param[in]  str
 * 	structure describing the string to copy
 * @param[out] strData  
 * 	pointer (pass by reference) to a block of memory where the string will be copied
 * 	the pointer will be incremented by the number of bytes copied
 **/
void strPush(char **strData, struct ezinj_str str){
	// write the number of bytes we need to skip to get to the next string
	*(unsigned int *)(*strData) = sizeof(unsigned int) + str.len;
	*strData += sizeof(unsigned int);

	// write the string itself
	memcpy(*strData, str.str, str.len);
	*strData += str.len;
}


struct injcode_bearing *prepare_bearing(struct ezinj_ctx *ctx, int argc, char *argv[]){
	size_t dyn_ptr_size = argc * sizeof(char *);
	size_t dyn_str_size = 0;

	struct ezinj_str args[32];
	
	int num_strings = 0;
	int argi = 0;
	off_t argv_offset = 0;

#define PUSH_STRING(str) do { \
	args[argi] = ezstr_new(str); \
	dyn_str_size += args[argi].len + sizeof(unsigned int); \
	argi++; \
	num_strings++; \
} while(0)

	// libdl.so name (without path)
	PUSH_STRING(DL_LIBRARY_NAME);
	// libpthread.so name (without path)
	PUSH_STRING(PTHREAD_LIBRARY_NAME);

#if defined(EZ_TARGET_POSIX)
	PUSH_STRING("dlerror");
	PUSH_STRING("pthread_mutex_init");
	PUSH_STRING("pthread_mutex_lock");
	PUSH_STRING("pthread_mutex_unlock");
	PUSH_STRING("pthread_cond_init");
	PUSH_STRING("pthread_cond_wait");
	PUSH_STRING("pthread_join");
#elif defined(EZ_TARGET_WINDOWS)
	PUSH_STRING("CreateEventA");
	PUSH_STRING("CreateThread");
	PUSH_STRING("CloseHandle");
	PUSH_STRING("WaitForSingleObject");
	PUSH_STRING("GetExitCodeThread");
#endif

	PUSH_STRING("crt_init");

	// library to load
	char libName[PATH_MAX];
#if defined(EZ_TARGET_POSIX)
	if(!realpath(argv[0], libName)) {
		ERR("realpath: %s", libName);
		PERROR("realpath");
		return NULL;
	}
#elif defined(EZ_TARGET_WINDOWS)
	{
		int size = GetFullPathNameA(argv[0], 0, NULL, NULL);
		GetFullPathNameA(argv[0], sizeof(libName), libName, NULL);
	}
#endif

	argv_offset = dyn_str_size;
	PUSH_STRING(libName);

	// user arguments
	for(int i=1; i < argc; i++){
		PUSH_STRING(argv[i]);
	}
#undef PUSH_STRING

	size_t dyn_total_size = dyn_ptr_size + dyn_str_size;
	size_t mapping_size;

	if(allocate_shm(ctx, dyn_total_size, &ctx->pl, &mapping_size) != 0){
		ERR("Could not allocate shared memory");
		return NULL;
	}

	struct injcode_bearing *br = (struct injcode_bearing *)ctx->mapped_mem.local;
	memset(br, 0x00, sizeof(*br));

	if(!br){
		PERROR("malloc");
		return NULL;
	}
	br->mapping_size = mapping_size;

	br->pl_debug = ctx->pl_debug;

	br->libdl_handle = (void *)ctx->libdl.remote;
#if defined(HAVE_DL_LOAD_SHARED_LIBRARY)
	br->uclibc_sym_tables = (void *)ctx->uclibc_sym_tables.remote;
	br->uclibc_dl_fixup = (void *)ctx->uclibc_dl_fixup.remote;
	br->uclibc_loaded_modules = (void *)ctx->uclibc_loaded_modules.remote;
#ifdef EZ_ARCH_MIPS
	br->uclibc_mips_got_reloc = (void *)ctx->uclibc_mips_got_reloc.remote;
#endif
#endif

#ifdef EZ_TARGET_WINDOWS
	br->RtlGetCurrentPeb = (void *)ctx->nt_get_peb.remote;
	br->NtQueryInformationProcess = (void *)ctx->nt_query_proc.remote;
	br->NtWriteFile = (void *)ctx->nt_write_file.remote;
#endif

	br->dlopen_offset = ctx->dlopen_offset;
	br->dlclose_offset = ctx->dlclose_offset;
	br->dlsym_offset = ctx->dlsym_offset;

#define USE_LIBC_SYM(name) do { \
	br->libc_##name = (void *)ctx->libc_##name.remote; \
	DBGPTR(br->libc_##name); \
} while(0)

	USE_LIBC_SYM(dlopen);

	USE_LIBC_SYM(syscall);
#undef USE_LIBC_SYM

	br->argc = argc;
	br->dyn_size = dyn_total_size;
	br->num_strings = num_strings;
	br->argv_offset = argv_offset;

	char *stringData = (char *)br + sizeof(*br) + dyn_ptr_size;
	for(int i=0; i<num_strings; i++){
		strPush(&stringData, args[i]);
	}

	// copy code
	memcpy(ctx->pl.code_start, region_pl_code.start, REGION_LENGTH(region_pl_code));

	return br;
}

int allocate_shm(struct ezinj_ctx *ctx, size_t dyn_total_size, struct ezinj_pl *layout, size_t *allocated_size){
	// br + argv
	size_t br_size = (size_t)WORDALIGN(sizeof(struct injcode_bearing) + dyn_total_size);
	// size of code payload
	size_t code_size = (size_t)WORDALIGN(REGION_LENGTH(region_pl_code));

	size_t stack_offset = br_size + code_size;
	size_t mapping_size = stack_offset + PL_STACK_SIZE;

	DBG("br_size=%zu", br_size);
	DBG("code_size=%zu", code_size);
	DBG("stack_offset=%zu", stack_offset);
	DBG("mapping_size=%zu", mapping_size);

	#ifdef USE_SHM
	int shm_id;
	if((shm_id = shmget(ctx->target, mapping_size, IPC_CREAT | IPC_EXCL | S_IRWXU | S_IRWXG | S_IRWXO)) < 0){
		PERROR("shmget");
		return 1;
	}
	INFO("SHM id: %u", shm_id);
	ctx->shm_id = shm_id;

	void *mapped_mem = shmat(shm_id, NULL, SHM_EXEC);
	if(mapped_mem == MAP_FAILED){
		PERROR("shmat");
		return 1;
	}
	#else
	void *mapped_mem = calloc(1, mapping_size);
	#endif

	ctx->mapped_mem.local = (uintptr_t)mapped_mem;

	*allocated_size = mapping_size;

	/** prepare payload layout **/

	uint8_t *pMem = (uint8_t *)ctx->mapped_mem.local;
	layout->br_start = pMem;
	pMem += br_size;

	layout->code_start = pMem;

	// stack is located at the end of the memory map
	layout->stack_top = (uint8_t *)ctx->mapped_mem.local + mapping_size;

	/** align stack **/

	#if defined(EZ_ARCH_AMD64) || defined(EZ_ARCH_ARM64)
	// x64 requires a 16 bytes aligned stack for movaps
	// force stack to snap to the lowest 16 bytes, or it will crash on x64
	layout->stack_top = (uint8_t *)((uintptr_t)layout->stack_top & ~ALIGNMSK(16));
	#else
	layout->stack_top = (uint8_t *)((uintptr_t)layout->stack_top & ~ALIGNMSK(sizeof(void *)));
	#endif
	return 0;
}

void cleanup_mem(struct ezinj_ctx *ctx){
	#ifdef USE_SHM
	if(ctx->mapped_mem.local != 0){
		if(shmdt((void *)ctx->mapped_mem.local) < 0){
			PERROR("shmdt");
		} else {
			ctx->mapped_mem.local = 0;
		}
	}
	if(ctx->shm_id > -1){
		if(shmctl(ctx->shm_id, IPC_RMID, NULL) < 0){
			PERROR("shmctl (IPC_RMID)");
		} else {
			ctx->shm_id = -1;
		}
	}
	#else
	free((void *)ctx->mapped_mem.local);
	#endif
}

void sigint_handler(int signum){
	UNUSED(signum);
	cleanup_mem(&ctx);
}

#if defined(EZ_TARGET_LINUX)
void print_maps(){
	pid_t pid = syscall(__NR_getpid);
	char *path;
	asprintf(&path, "/proc/%u/maps", pid);
	do {
		FILE *fh = fopen(path, "r");
		if(!fh){
			return;
		}
		
		char line[256];
		while(!feof(fh)){
			fgets(line, sizeof(line), fh);
			fputs(line, stdout);
		}
		fclose(fh);
	} while(0);
	free(path);
}
#else
void print_maps(){}
#endif

int ezinject_main(
	struct ezinj_ctx *ctx,
	int argc, char *argv[]
){
	print_maps();

	signal(SIGINT, sigint_handler);

	// allocate bearing on shared memory
	struct injcode_bearing *br = prepare_bearing(ctx, argc, argv);
	if(br == NULL){
		return -1;
	}

	if(remote_sc_alloc(ctx) != 0){
		ERR("remote_sc_alloc failed");
		return -1;
	}

	// wait for a single syscall
	ctx->syscall_mode = 1;

	/* Verify that remote_call works correctly */
	if(remote_sc_check(ctx) != 0){
		ERR("remote_sc_check failed");
		return -1;
	}

	intptr_t err = -1;
	do {
		uintptr_t remote_shm_ptr = remote_pl_alloc(ctx, br->mapping_size);
		if(remote_shm_ptr == 0){
		#ifdef EZ_TARGET_WINDOWS
			PERROR("VirtualAllocEx failed");
		#else
			ERR("Remote shmat failed: %p", (void *)remote_shm_ptr);
		#endif
			break;
		}
		DBG("remote payload base: %p", (void *)remote_shm_ptr);

		ctx->mapped_mem.remote = remote_shm_ptr;

		struct ezinj_pl *pl = &ctx->pl;

		#define PL_REMOTE(pl_addr) \
			UPTR(remote_shm_ptr + PTRDIFF(pl_addr, ctx->mapped_mem.local))

		#define PL_REMOTE_CODE(addr) \
			PL_REMOTE(pl->code_start) + PTRDIFF(addr, region_pl_code.start)

		#ifdef __GNUC__
		{
			void *flush_start = br;
			void *flush_end = (void *)(UPTR(br) + br->mapping_size);
			__builtin___clear_cache(flush_start, flush_end);
		}
		#else
		usleep(50000);
		#endif

		
		#ifndef USE_SHM
		if(remote_write(ctx, ctx->mapped_mem.remote, (void *)ctx->mapped_mem.local, br->mapping_size) != br->mapping_size){
			PERROR("remote_write failed");
		}		
		#endif

		// switch to SIGSTOP wait mode
		ctx->syscall_mode = 0;

		// switch to user stack
		uintptr_t *target_sp = (uintptr_t *)pl->stack_top;
		ctx->pl_stack.remote = (uintptr_t)PL_REMOTE(target_sp);

		// set trampoline parameters
		ctx->branch_target.remote = PL_REMOTE_CODE(&injected_fn);
		ctx->trampoline_insn.remote = PL_REMOTE_CODE(&trampoline_entry);

		DBG("\n"
			"==== call chain:\n"
			"0: %p [trampoline]\n"
			"1: %p [wrapper]\n" 
			"2: %p [target]\n",
			ctx->trampoline_insn.remote,
			get_wrapper_address(ctx),
			ctx->branch_target.remote
		);

		err = CHECK(RSCALL0(ctx, PL_REMOTE(pl->br_start)));

		/**
		 * if payload debugging is on, skip any cleanup
		 **/
		if(ctx->pl_debug){
			return -1;
		}

		// restore syscall behavior (to call shmdt, if needed by the target)
		ctx->syscall_mode = 1;
		ctx->pl_stack.remote = 0;
		remote_pl_free(ctx, remote_shm_ptr);

		if(remote_sc_free(ctx) != 0){
			ERR("remote_sc_free failed!");
			return -1;
		}
	} while(0);

	return err;
}

int main(int argc, char *argv[]){
	if(argc < 3) {
		ERR("Usage: %s pid library-to-inject", argv[0]);
		return 1;
	}

#ifdef DEBUG
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
#endif

	memset(&ctx, 0x00, sizeof(ctx));

	{
		int c;
		while ((c = getopt (argc, argv, "d")) != -1){
			switch(c){
				case 'd':
					WARN("payload debugging enabled, the target **WILL** freeze");
					ctx.pl_debug = 1;
					break;
			}
		}
	}

	const char *argPid = argv[optind++];
	ctx.target = strtoul(argPid, NULL, 10);
	INFO("Attaching to %u", ctx.target);

	if(remote_attach(&ctx) < 0){
		PERROR("remote_attach failed");
		return 1;
	}

	INFO("waiting for target to stop...");

	int err = 0;
	if(remote_wait(&ctx, 0) < 0){
		PERROR("remote_wait");
		return 1;
	}

	if(libc_init(&ctx) != 0){
		return 1;
	}

	err = ezinject_main(&ctx, argc - optind, &argv[optind]);
	/**
	 * due to an eglibc bug, libdl loading will fail even tho it actually worked
	 * if we're targeting linux, try again
	 */
	#ifdef EZ_TARGET_LINUX
	if(err == INJ_ERR_LIBDL){
		cleanup_mem(&ctx);
		if(libc_init(&ctx) != 0){
			return 1;
		}
		err = ezinject_main(&ctx, argc - optind, &argv[optind]);
	}
	#endif


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
