#ifndef __EZINJECT_AARCH64_H
#define __EZINJECT_AARCH64_H

#define REG_PC pc
#define REG_SP sp
#define REG_NR regs[8]
#define REG_RET regs[0]
#define REG_ARG1 regs[0]
#define REG_ARG2 regs[1]
#define REG_ARG3 regs[2]
#define REG_ARG4 regs[3]
#define REG_ARG5 regs[4]
#define REG_ARG6 regs[5]

#define REG(u, r) (u).r

#define EMIT_SC() asm volatile("svc #0\n")
#define EMIT_BP() asm volatile("bkpt #0\n")
#define EMIT_LDP(var1, var2) asm volatile("ldp %0, %1, [sp], #16" : "=r"(var1), "=r"(var2))

#define POP_PARAMS(out_br, out_func) \
	EMIT_LDP(out_br, out_func);

#define JMP_INSN "b"

typedef struct user_pt_regs regs_t;

#endif