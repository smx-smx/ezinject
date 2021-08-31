#ifndef __EZINJECT_ARM_H
#define __EZINJECT_ARM_H

#include "config.h"

#define REG_PC uregs[15]
#define REG_SP uregs[13]

#define REG(u, r) (u).regs.r

#ifdef USE_ARM_THUMB
#define EMIT_POP(var) \
	asm volatile( \
		"ldr %0, [sp]\n" \
		"add sp, sp, #4" \
	: "=r"(var));
#else
#define EMIT_POP(var) asm volatile("ldr %0, [sp], #4" : "=r"(var))
#endif


#define POP_PARAMS(out_br, out_func) \
	EMIT_POP(out_br); \
	EMIT_POP(out_func)

#define JMP_INSN "b"

typedef struct user regs_t;

#endif