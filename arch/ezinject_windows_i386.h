#ifndef __EZINJECT_I386_H
#define __EZINJECT_I386_H

#define REG_PC Eip
#define REG_SP Esp
#define REG_AX Eax

#define REG(u, r) (u).r

#define EMIT_POP(var) asm volatile("pop %0" : "=r"(var))

#define POP_PARAMS(out_br, out_func) \
	EMIT_POP(out_func); \
	EMIT_POP(out_br)

#define JMP_INSN "jmp"

#include <windows.h>
#include <winnt.h>
typedef CONTEXT regs_t;

#endif
