#ifndef __EZINJECT_MIPS_H
#define __EZINJECT_MIPS_H

#define REG_PC cp0_epc
#define REG_SP regs[29]

#define REG(u, r) (u).r

#define EMIT_POP(var) asm volatile( \
	"lw %0, 0($sp)\n" \
	"addiu $sp, $sp, 4\n" \
	: "=r"(var))

#define POP_PARAMS(out_br, out_func) \
	EMIT_POP(out_br); \
	EMIT_POP(out_func)

#define JMP_INSN "j"

// the bundled pt_regs definition is wrong (https://www.linux-mips.org/archives/linux-mips/2014-07/msg00443.html)
// so we must provide our own

struct pt_regs2 {
	uint64_t regs[32];
	uint64_t lo;
	uint64_t hi;
	uint64_t cp0_epc;
	uint64_t cp0_badvaddr;
	uint64_t cp0_status;
	uint64_t cp0_cause;
} __attribute__ ((aligned (8)));
typedef struct pt_regs2 regs_t;

#endif