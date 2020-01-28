#ifndef __EZINJECT_ARM_H
#define __EZINJECT_ARM_H

#define REG_PC uregs[15]
#define REG_SP uregs[13]
#define REG_NR uregs[7]
#define REG_RET uregs[0]
#define REG_ARG1 uregs[0]
#define REG_ARG2 uregs[1]
#define REG_ARG3 uregs[2]
#define REG_ARG4 uregs[3]
#define REG_ARG5 uregs[4]
#define REG_ARG6 uregs[5]

#define REG(u, r) (u).regs.r

#define EMIT_SC() asm volatile("swi 0\n")
#define EMIT_POP(var) asm volatile("pop {%0}" : "=r"(var))


#endif