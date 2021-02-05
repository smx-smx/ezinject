#ifndef __EZINJECT_AARCH64_H
#define __EZINJECT_AARCH64_H

#define REG_PC pc
#define REG_SP sp

#define REG(u, r) (u).r

#define EMIT_LDP(var1, var2) asm volatile("ldp %0, %1, [sp], #16" : "=r"(var1), "=r"(var2))

#define POP_PARAMS(out_br, out_func) \
	EMIT_LDP(out_br, out_func);

#define JMP_INSN "b"

typedef struct user_pt_regs regs_t;

#endif