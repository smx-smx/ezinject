#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sched.h>
#ifdef __mips
#include <linux/shm.h>
#endif
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/shm.h>
#include <sys/user.h>

#define CHECK(x) ({\
long _tmp = (x);\
DBG("%s = %lu", #x, _tmp);\
_tmp;})

#include "util.h"
#include "ezinject_injcode.h"

enum verbosity_level verbosity = V_DBG;

#if defined(__arm__)
#define REG_PC uregs[15]
#define REG_NR uregs[7]
#define REG_RET uregs[0]
#define REG_ARG1 uregs[0]
#define REG_ARG2 uregs[1]
#define REG_ARG3 uregs[2]
#define REG_ARG4 uregs[3]
#define REG_ARG5 uregs[4]
#define REG_ARG6 uregs[5]
const char SYSCALL_INSN[] = {0x00, 0x00, 0x00, 0xef}; /* swi 0 */
const char RET_INSN[] = {0x04, 0xf0, 0x9d, 0xe4}; /* pop {pc} */
#elif defined(__i386__)
#define REG_PC eip
#define REG_NR eax
#define REG_RET eax
#define REG_ARG1 ebx
#define REG_ARG2 ecx
#define REG_ARG3 edx
#define REG_ARG4 esi
#define REG_ARG5 edi
#define REG_ARG6 ebp
const char SYSCALL_INSN[] = {0xcd, 0x80}; /* int 0x80 */
const char RET_INSN[] = {0xc3}; /* ret */
#elif defined(__amd64__)
#define REG_PC rip
#define REG_NR rax
#define REG_RET rax
#define REG_ARG1 rdi
#define REG_ARG2 rsi
#define REG_ARG3 rdx
#define REG_ARG4 r10
#define REG_ARG5 r8
#define REG_ARG6 r9
const char SYSCALL_INSN[] = {0x0f, 0x05}; /* syscall */
const char RET_INSN[] = {0xc3}; /* ret */
#elif defined(__mips__)
#define REG_PC regs[EF_CP0_EPC]
#define REG_RET regs[2] //$v0
#define REG_NR regs[2] //$v0
#define REG_ARG1 regs[4] //$a0
#define REG_ARG2 regs[5] //$a1
#define REG_ARG3 regs[6] //$a2
#define REG_ARG4 regs[7] //$a3
char SYSCALL_INSN[] = {0x00, 0x00, 0x00, 0x0c}; //syscall
char RET_INSN[] = {
	0x8f, 0xbf, 0x00, 0x00, //lw $ra, 0($sp)
	0x23, 0xbd, 0x00, 0x04, //addi $sp, $sp, 4
	0x03, 0xe0, 0x00, 0x08  //jr $ra
};

static int isBigEndian(){
	int i=1;
    return ! *((char *)&i);
}
#else
#error "Unsupported architecture"
#endif

#ifndef __NR_mmap
#define __NR_mmap __NR_mmap2 /* Functionally equivalent for our use case. */
#endif

#define MAPPINGSIZE 4096
#define MEMALIGN 4 /* MUST be a power of 2 */
#define ALIGNMSK ~(MEMALIGN-1)

#define ALIGN(x) ((void *)(((uintptr_t)x + MEMALIGN) & ALIGNMSK))

#define CLONE_FLAGS (CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_PARENT|CLONE_THREAD|CLONE_IO)

typedef struct {
	uintptr_t base_remote;
	uintptr_t base_local;
} ez_addr;

#define EZ_LOCAL(ref, remote) (ref.base_local + (((uintptr_t)remote) - ref.base_remote))
#define EZ_REMOTE(ref, local) (ref.base_remote + (((uintptr_t)local) - ref.base_local))


uintptr_t remote_call(pid_t target, void *insn_addr, int nr, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4)
{
	struct user orig_ctx, new_ctx;
	memset(&orig_ctx, 0x00, sizeof(orig_ctx));

	ptrace(PTRACE_GETREGS, target, 0, &orig_ctx);
	memcpy(&new_ctx, &orig_ctx, sizeof(orig_ctx));

	new_ctx.regs.REG_PC = (uintptr_t)insn_addr;
	new_ctx.regs.REG_NR = nr;
	new_ctx.regs.REG_ARG1 = arg1;
	new_ctx.regs.REG_ARG2 = arg2;
	new_ctx.regs.REG_ARG3 = arg3;
	new_ctx.regs.REG_ARG4 = arg4;
	/*new_ctx.regs.REG_ARG5 = arg5;
	new_ctx.regs.REG_ARG6 = arg6;*/
	ptrace(PTRACE_SETREGS, target, 0, &new_ctx);

	ptrace(PTRACE_SYSCALL, target, 0, 0); /* Run until syscall entry */
	waitpid(target, 0, 0);
	ptrace(PTRACE_SYSCALL, target, 0, 0); /* Run until syscall return */
	waitpid(target, 0, 0);
	ptrace(PTRACE_GETREGS, target, 0, &new_ctx); /* Get return value */
	
	ptrace(PTRACE_SETREGS, target, 0, &orig_ctx);
	DBG("remote_call(%d) = %zu", nr, (uintptr_t)new_ctx.regs.REG_RET);

	return new_ctx.regs.REG_RET;
}

void *locate_gadget(uint8_t *base, size_t limit, uint8_t *search, size_t searchSz){
	for(size_t i = 0; i < limit; ++i)
	{
		if(!memcmp(&base[i], search, searchSz))
		{
			return (void *)&base[i];
		}
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	char buf[128];
	char sopath[PATH_MAX];
	int err = 0;
	if(argc != 3)
	{
		ERR("Usage: %s pid library-to-inject", argv[0]);
		return 1;
	}
	pid_t target = atoi(argv[1]);
	snprintf(buf, 128, "/proc/%u/exe", target);

	if(!realpath(argv[2], sopath))
	{
		PERROR("realpath");
		return 1;
	}

	#ifdef __mips__
	if(!isBigEndian()){
		*(uint32_t *)SYSCALL_INSN = __builtin_bswap32(*(uint32_t *)SYSCALL_INSN);
		uint32_t *ret_ptr = (uint32_t *)RET_INSN;
		ret_ptr[0] = __builtin_bswap32(ret_ptr[0]);
		ret_ptr[1] = __builtin_bswap32(ret_ptr[1]);
		ret_ptr[2] = __builtin_bswap32(ret_ptr[2]);
	}
	#endif

	/**
	 * locate glibc in /proc/<pid>/maps
	 * both for local and remote procs
	 */
	ez_addr libc = {
		.base_local  = (uintptr_t) get_base(getpid(), "libc-"),
		.base_remote = (uintptr_t) get_base(target, "libc-")
	};

	DBGPTR(libc.base_remote);
	DBGPTR(libc.base_local);
	
	if(!libc.base_local || !libc.base_remote)
	{
		ERR("Failed to get libc base");
		return 1;
	}

	ez_addr libc_syscall = {
		.base_local  = (uintptr_t)&syscall,
		.base_remote = EZ_REMOTE(libc, &syscall)
	};

	ez_addr libc_syscall_insn = {
		.base_local = (uintptr_t)locate_gadget(
			(uint8_t *)libc_syscall.base_local, 0x1000,
			(uint8_t *)SYSCALL_INSN,
			sizeof(SYSCALL_INSN)
		),
	};
	libc_syscall_insn.base_remote = EZ_REMOTE(libc, libc_syscall_insn.base_local);

	if(!libc_syscall_insn.base_local)
	{
		ERR("Failed to find syscall instruction in libc");
		err = 1;
		return 1;
	}

	DBGPTR(libc_syscall_insn.base_local);
	CHECK(ptrace(PTRACE_ATTACH, target, 0, 0));

	/* Wait for attached process to stop */
	{
		pid_t proc_pid;
		int status = 0;
		while ((proc_pid=waitpid(target, &status, __WALL | WUNTRACED)) != target && proc_pid >= 0){
			DBG("Skipping process '%d'", proc_pid);
		}
	}

	#define REMOTE_SC(nr, arg0, arg1, arg2, arg3) \
		remote_call(target, (void *)libc_syscall_insn.base_remote, nr, arg0, arg1, arg2, arg3)
	
	/* Verify that remote_call works correctly */
	pid_t remote_pid = REMOTE_SC(__NR_getpid, 0, 0, 0, 0);
	if(remote_pid != target)
	{
		ERR("Remote syscall returned incorrect result!");
		ERR("Expected: %u, actual: %u", target, remote_pid);
		err = 1;
		goto cleanup_ptrace;
	}

	int shm_id;
	if((shm_id = shmget(target, MAPPINGSIZE, IPC_CREAT | IPC_EXCL | S_IRWXO)) < 0){
		PERROR("shmget");
		return 1;
	}

	char *mapped_mem = shmat(shm_id, NULL, SHM_EXEC);
	if(mapped_mem == MAP_FAILED){
		PERROR("shmat");
		err = 1;
		goto cleanup_shm;
	}
	
	size_t injected_size = (size_t)(injected_code_end - (uintptr_t)injected_code);
	
	DBG("injsize=%zu", injected_size);
	
	/* Copy code */
	memcpy(mapped_mem, injected_code, injected_size);
	
	/* Install syscall->ret gadget (will be used when creating thread) */
	char *syscall_ret_gadget = ALIGN(mapped_mem + injected_size);
	DBGPTR(syscall_ret_gadget);
	
	// copy 'syscall' insn
	memcpy(syscall_ret_gadget, (void*)SYSCALL_INSN, sizeof(SYSCALL_INSN));
	DBGPTR(syscall_ret_gadget + sizeof(SYSCALL_INSN));

	// copy 'ret' insn
	memcpy(syscall_ret_gadget + sizeof(SYSCALL_INSN), (void*)RET_INSN, sizeof(RET_INSN));
	char *syscall_ret_gadget_end = syscall_ret_gadget + sizeof(SYSCALL_INSN) + sizeof(RET_INSN);

	#define GETSYM(sym) { \
		.base_local = (uintptr_t) (sym), \
		.base_remote = (uintptr_t) EZ_REMOTE(libc, (uintptr_t)(sym)) \
	}

	/**
	 * Rebase local symbols to remote
	 */
	ez_addr libc_dlopen_mode = GETSYM(dlsym(RTLD_DEFAULT, "__libc_dlopen_mode"));
	ez_addr libc_shmget = GETSYM(&shmget);
	ez_addr libc_shmat = GETSYM(&shmat);
	ez_addr libc_shmdt = GETSYM(&shmdt);

	DBGPTR(libc_dlopen_mode.base_remote);	
	struct injcode_bearing br =
	{
		.libc_dlopen_mode = (void *)libc_dlopen_mode.base_remote,
		.libc_syscall = (void *)libc_syscall.base_remote,
		.libc_shmget = (void *)libc_shmget.base_remote,
		.libc_shmat = (void *)libc_shmat.base_remote,
		.libc_shmdt = (void *)libc_shmdt.base_remote
	};
	strncpy(br.libname, sopath, sizeof(br.libname));
	char *target_bearing = ALIGN(syscall_ret_gadget_end);
	memcpy(target_bearing, &br, sizeof(struct injcode_bearing));
	
	DBGPTR(mapped_mem);
	DBGPTR(syscall_ret_gadget);
	DBGPTR(target_bearing);

	//int remote_shm_id = (int)CHECK(REMOTE_SC(__NR_shmget, target, MAPPINGSIZE, S_IRWXO, 0));
	int remote_shm_id = (int)CHECK(remote_call(target, (void *)libc_shmget.base_remote, 0, target, MAPPINGSIZE, S_IRWXO, 0));
	if(remote_shm_id < 0){
		ERR("Remote shmget failed: %d", remote_shm_id);
		goto cleanup_shm;
	}
	INFO("Shm id: %d", remote_shm_id);

	uintptr_t remote_shm_ptr = CHECK(remote_call(target, (void *)libc_shmat.base_remote, 0, remote_shm_id, 0, SHM_EXEC, 0));
	if(remote_shm_ptr == (uintptr_t)MAP_FAILED){
		ERR("Remote shmat failed: %p", (void *)remote_shm_ptr);
		goto cleanup_shm;
	}

	#define PL_REMOTE(pl_addr) ((void *)(remote_shm_ptr + ((uintptr_t)(pl_addr) - (uintptr_t)mapped_mem)))

	uintptr_t *target_sp = (uintptr_t *)(mapped_mem + MAPPINGSIZE - (sizeof(void *) * 2));
	target_sp[0] = (uintptr_t)remote_shm_ptr; //code base
	target_sp[1] = (uintptr_t)PL_REMOTE(target_bearing);
	
	DBGPTR(target_sp[0]);
	DBGPTR(target_sp[1]);

	char *target_syscall_ret = PL_REMOTE(syscall_ret_gadget);
	#define REMOTE_SC_RET(nr, arg0, arg1, arg2, arg3) remote_call(target, (void *)target_syscall_ret, nr, arg0, arg1, arg2, arg3)

	if(shmdt(mapped_mem) < 0){
		PERROR("shmdt");
	}

	/* Make the call */
	/* !! VERY IMPORTANT !! */
	/* Use the syscall->ret gadget to make the new thread safely "return" to its entrypoint */
	pid_t tid = CHECK(REMOTE_SC_RET(__NR_clone, CLONE_FLAGS, (uintptr_t)PL_REMOTE(target_sp), 0, 0));
	/* Wait for new thread to exit before unmapping its memory */
	CHECK(tid);
	do
	{
		usleep(100);
	} while(kill(tid, 0) != -1); /* TODO this is vulnerable to a race condition */
	/* What if the new thread dies, and a new process spawns and takes its pid? */
	/* Unluckily it is impossible to waitpid() for a process you don't own. */

cleanup_shm:
	// mark shared memory for deletion, when the process dies
	CHECK(shmctl(shm_id, IPC_RMID, NULL));

cleanup_ptrace:
	CHECK(ptrace(PTRACE_DETACH, target, 0, 0));
	return err;
}
