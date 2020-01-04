#ifndef __EZINJECT_MIPS_H
#define __EZINJECT_MIPS_H

#define REG_PC regs[EF_CP0_EPC]
#define REG_RET regs[2] //$v0
#define REG_NR regs[2] //$v0
#define REG_ARG1 regs[4] //$a0
#define REG_ARG2 regs[5] //$a1
#define REG_ARG3 regs[6] //$a2
#define REG_ARG4 regs[7] //$a3
char SYSCALL_INSN[] = {0x00, 0x00, 0x00, 0x0c}; //syscall
char RET_INSN[] = {
	0x8f, 0xbf, 0x00, 0x00, //lw $ra, 0($sp)
	0x23, 0xbd, 0x00, 0x04, //addi $sp, $sp, 4
	0x03, 0xe0, 0x00, 0x08  //jr $ra
};

#endif