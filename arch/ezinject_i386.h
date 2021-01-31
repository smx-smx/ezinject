#ifndef __EZINJECT_ARCH_I386
#define __EZINJECT_ARCH_I386

#define REG_PC eip
#define REG_SP esp
#define REG_NR eax
#define REG_RET eax
#define REG_ARG1 ebx
#define REG_ARG2 ecx
#define REG_ARG3 edx
#define REG_ARG4 esi
#define REG_ARG5 edi
#define REG_ARG6 ebp

#define REG(u, r) (u).regs.r

#define EMIT_SC() asm volatile("sysenter\n")
#define EMIT_BP() asm volatile("int $3\n")
#define EMIT_POP(var) asm volatile("pop %0" : "=r"(var))

#define POP_PARAMS(out_br, out_func) \
	EMIT_POP(out_br); \
	EMIT_POP(out_func)

#define JMP_INSN "jmp"

typedef struct user regs_t;

#endif