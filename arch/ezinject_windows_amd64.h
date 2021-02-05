#ifndef __EZINJECT_AMD64_H
#define __EZINJECT_AMD64_H

#define REG_PC Rip
#define REG_SP Rsp

#define REG(u, r) (u).r

#define EMIT_POP(var) asm volatile("pop %0" : "=r"(var))

#define POP_PARAMS(out_br, out_func) \
	EMIT_POP(out_br); \
	EMIT_POP(out_func)

#define JMP_INSN "jmp"

#include <windows.h>
#include <winnt.h>
typedef CONTEXT regs_t;

#endif