#ifndef __EZINJECT_ARCH_I386
#define __EZINJECT_ARCH_I386

#include <machine/reg.h>

#define _CONCAT(x,y) x##y
#define CONCAT(x,y) _CONCAT(x,y)

#define REG_PC eip
#define REG_SP esp
#define REG_NR eax
#define REG_RET eax

#define REG(u, reg) (u).CONCAT(r_,reg)

#define EMIT_SC() asm volatile("int $0x80\n")
#define EMIT_BP() asm volatile("int $3\n")
#define EMIT_POP(var) asm volatile("pop %0" : "=r"(var))

#define POP_PARAMS(out_br, out_func) \
	EMIT_POP(out_br); \
	EMIT_POP(out_func)

#define JMP_INSN "jmp"

typedef struct reg regs_t;

#endif