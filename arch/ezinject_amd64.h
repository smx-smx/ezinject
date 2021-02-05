#ifndef __EZINJECT_AMD64_H
#define __EZINJECT_AMD64_H

#define REG_PC rip
#define REG_SP rsp

#define REG(u, r) (u).regs.r

#define EMIT_POP(var) asm volatile("pop %0" : "=r"(var))

#define POP_PARAMS(out_br, out_func) \
	EMIT_POP(out_br); \
	EMIT_POP(out_func)

#define JMP_INSN "jmp"

typedef struct user regs_t;

#endif