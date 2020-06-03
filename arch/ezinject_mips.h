#ifndef __EZINJECT_MIPS_H
#define __EZINJECT_MIPS_H

#define REG_PC cp0_epc
#define REG_SP regs[29]
#define REG_RET regs[2] //$v0
#define REG_NR regs[2] //$v0
#define REG_ARG1 regs[4] //$a0
#define REG_ARG2 regs[5] //$a1
#define REG_ARG3 regs[6] //$a2
#define REG_ARG4 regs[7] //$a3

#define REG(u, r) (u).r

/**
 * zero after syscall used as stack, for arg4 in sys_ipc (used as shmaddr, which must be 0)
 **/
#define EMIT_SC() asm volatile( \
	"syscall\n" \
	".word 0x00\n" \
)

#define EMIT_POP(var) asm volatile( \
	"lw %0, 0($sp)\n" \
	"addiu $sp, $sp, 4\n" \
	: "=r"(var))
#endif