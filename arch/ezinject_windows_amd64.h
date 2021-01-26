#ifndef __EZINJECT_AMD64_H
#define __EZINJECT_AMD64_H

#define REG_PC Rip
#define REG_SP Rsp
#define REG_RET Rax
#define REG_ARG1 Rcx
#define REG_ARG2 Rdx
#define REG_ARG3 R8
#define REG_ARG4 R9

#define REG(u, r) (u).r

#define EMIT_SC() asm volatile("syscall\n")
#define EMIT_POP(var) asm volatile("pop %0" : "=r"(var))

#define POP_PARAMS(out_br, out_func) \
	EMIT_POP(out_br); \
	EMIT_POP(out_func)

#define JMP_INSN "jmp"

#include <windows.h>
#include <winnt.h>
typedef CONTEXT regs_t;

#endif