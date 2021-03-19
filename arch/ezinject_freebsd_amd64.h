#ifndef __EZINJECT_FREEBSD_AMD64_H
#define __EZINJECT_FREEBSD_AMD64_H

#include <machine/reg.h>

#define _CONCAT(x,y) x##y
#define CONCAT(x,y) _CONCAT(x,y)
#define REG(u, reg) (u).CONCAT(r_,reg)

#define REG_PC rip
#define REG_SP rsp

#define EMIT_POP(var) asm volatile("pop %0" : "=r"(var))

#define POP_PARAMS(out_br, out_func) \
	EMIT_POP(out_br); \
	EMIT_POP(out_func)

#define JMP_INSN "jmp"

typedef struct reg regs_t;

#endif