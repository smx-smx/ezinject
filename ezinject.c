#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

#define CHECK(x) ({\
long _tmp = (x);\
DBG("%s = %lu", #x, _tmp);\
_tmp;})

#include "util.h"
#include "elfparse.h"
#include "ezinject_injcode.h"

enum verbosity_level verbosity = V_INFO;

#if defined(__arm__)
#define regs user_regs
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
#define regs user_regs_struct
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
#define regs user_regs_struct
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
#else
#error "Unsupported architecture"
#endif

#ifndef __NR_mmap
#define __NR_mmap __NR_mmap2 /* Functionally equivalent for our use case. */
#endif

uintptr_t remote_syscall(pid_t target, void *syscall_addr, int nr, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5, uintptr_t arg6)
{
	struct regs orig_regs, new_regs;
	ptrace(PTRACE_GETREGS, target, 0, &orig_regs);
	memcpy(&new_regs, &orig_regs, sizeof(struct regs));
	new_regs.REG_PC = (uintptr_t)syscall_addr;
	new_regs.REG_NR = nr;
	new_regs.REG_ARG1 = arg1;
	new_regs.REG_ARG2 = arg2;
	new_regs.REG_ARG3 = arg3;
	new_regs.REG_ARG4 = arg4;
	new_regs.REG_ARG5 = arg5;
	new_regs.REG_ARG6 = arg6;
	ptrace(PTRACE_SETREGS, target, 0, &new_regs);
	ptrace(PTRACE_SYSCALL, target, 0, 0); /* Run until syscall entry */
	waitpid(target, 0, 0);
	ptrace(PTRACE_SYSCALL, target, 0, 0); /* Run until syscall return */
	waitpid(target, 0, 0);
	ptrace(PTRACE_GETREGS, target, 0, &new_regs); /* Get return value */
	ptrace(PTRACE_SETREGS, target, 0, &orig_regs);
	DBG("remote_syscall(%d) = %zu", nr, (uintptr_t)new_regs.REG_RET);
	return new_regs.REG_RET;
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

	void *hndl = elfparse_createhandle(buf);
	if(!hndl)
	{
		ERR("Failed to parse ELF file %s", buf);
		return 1;
	}
	char *target_libc_base = get_base(target, "libc-");
	char *my_libc_base = get_base(getpid(), "libc-");

	DBGPTR(target_libc_base);
	DBGPTR(my_libc_base);
	
	if(!target_libc_base || !my_libc_base)
	{
		ERR("Failed to get libc base");
		err = 1;
		goto out_elfparse;
	}
	
	char *my_libc_syscall_func = dlsym(RTLD_DEFAULT, "syscall");
	void *target_libc_syscall_func = my_libc_syscall_func - (uintptr_t)my_libc_base + (uintptr_t)target_libc_base;
	char *my_libc_syscall_insn = 0;
	for(int i = 0; i < 0x1000; ++i)
	{
		if(!memcmp(&my_libc_syscall_func[i], SYSCALL_INSN, sizeof(SYSCALL_INSN)))
		{
			my_libc_syscall_insn = &my_libc_syscall_func[i];
			break;
		}
	}
	if(!my_libc_syscall_insn)
	{
		ERR("Failed to find syscall instruction in libc");
		err = 1;
		return 1;
	}
	char *target_libc_syscall_insn = my_libc_syscall_insn - (uintptr_t)my_libc_base + (uintptr_t)target_libc_base;
	DBGPTR(target_libc_syscall_insn);
	
	CHECK(ptrace(PTRACE_ATTACH, target, 0, 0));

	usleep(100);
	
	/* Verify that remote_syscall works correctly */
	pid_t remote_pid = remote_syscall(target, target_libc_syscall_insn, __NR_getpid, 0, 0, 0, 0, 0, 0);
	if(remote_pid != target)
	{
		ERR("Remote syscall returned incorrect result!");
		ERR("Expected: %u, actual: %u", target, remote_pid);
		err = 1;
		goto out_ptrace;
	}
	
#define MAPPINGSIZE 4096
#define MEMALIGN 4 /* MUST be a power of 2 */
#define ALIGNMSK ~(MEMALIGN-1)
	char *mapped_mem = (char *)remote_syscall(target, target_libc_syscall_insn, __NR_mmap, 0, MAPPINGSIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	
	size_t injected_size = (size_t)(injected_code_end - (uintptr_t)injected_code);
	
	DBG("injsize=%zu", injected_size);
	
	/* Copy code */
	CHECK(memcpy_to(target, mapped_mem, injected_code, injected_size));
	
	/* Install syscall->ret gadget (will be used when creating thread) */
	char *syscall_ret_gadget = mapped_mem + injected_size + MEMALIGN;
	syscall_ret_gadget = (char *)((uintptr_t)syscall_ret_gadget & ALIGNMSK);
	DBGPTR(syscall_ret_gadget);
	CHECK(memcpy_to(target, syscall_ret_gadget, (void*)SYSCALL_INSN, sizeof(SYSCALL_INSN)));
	usleep(100);
	DBGPTR(syscall_ret_gadget+sizeof(SYSCALL_INSN));
	CHECK(memcpy_to(target, syscall_ret_gadget + sizeof(SYSCALL_INSN), (void*)RET_INSN, sizeof(RET_INSN)));
	char *syscall_ret_gadget_end = syscall_ret_gadget + sizeof(SYSCALL_INSN) + sizeof(RET_INSN);

	/* Help the new thread get its bearings */
	char *my_libc_dlopen_mode = dlsym(RTLD_DEFAULT, "__libc_dlopen_mode");
	void *target_libc_dlopen_mode = my_libc_dlopen_mode - (uintptr_t)my_libc_base + (uintptr_t)target_libc_base;
	DBGPTR(target_libc_dlopen_mode);
	struct injcode_bearing br =
	{
		.libc_dlopen_mode = target_libc_dlopen_mode,
		.libc_syscall = target_libc_syscall_func
	};
	strncpy(br.libname, sopath, sizeof(br.libname));
	char *target_bearing = syscall_ret_gadget_end + MEMALIGN;
	target_bearing = (char *)((uintptr_t)target_bearing & ALIGNMSK);
	memcpy_to(target, target_bearing, &br, sizeof(struct injcode_bearing));

	/* Set up stack */
	void *stack[2] = {mapped_mem, target_bearing};
	void *target_sp = mapped_mem + MAPPINGSIZE - sizeof(stack);
	CHECK(memcpy_to(target, target_sp, stack, sizeof(stack)));
	
	DBGPTR(mapped_mem);
	DBGPTR(syscall_ret_gadget);
	DBGPTR(target_bearing);
	DBGPTR(target_sp);

	/* Make the call */
#define CLONE_FLAGS (CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_PARENT|CLONE_THREAD|CLONE_IO)
	/* !! VERY IMPORTANT !! */
	/* Use the syscall->ret gadget to make the new thread safely "return" to its entrypoint */
	pid_t tid = CHECK(remote_syscall(target, syscall_ret_gadget, __NR_clone, CLONE_FLAGS, (uintptr_t)target_sp, 0, 0, 0, 0));
	/* Wait for new thread to exit before unmapping its memory */
	do
	{
		usleep(100);
	} while(kill(tid, 0) != -1); /* TODO this is vulnerable to a race condition */
	/* What if the new thread dies, and a new process spawns and takes its pid? */
	/* Unluckily it is impossible to waitpid() for a process you don't own. */
	remote_syscall(target, target_libc_syscall_insn, __NR_munmap, (uintptr_t)mapped_mem, MAPPINGSIZE, 0, 0, 0, 0);

out_ptrace:
	CHECK(ptrace(PTRACE_DETACH, target, 0, 0));
out_elfparse:
	elfparse_destroyhandle(hndl);
	return err;
}
