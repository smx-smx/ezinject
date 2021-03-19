#ifndef __EZINJECT_ARCH_I386
#define __EZINJECT_ARCH_I386

#define REG_PC eip
#define REG_SP esp

#define REG(u, r) (u).regs.r

#define EMIT_POP(var) asm volatile("pop %0" : "=r"(var))

#define POP_PARAMS(out_br, out_func) \
	EMIT_POP(out_br); \
	EMIT_POP(out_func)

#define JMP_INSN "jmp"

typedef struct user regs_t;

#endif