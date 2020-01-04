#ifndef __EZINJECT_ARM_H
#define __EZINJECT_ARM_H

#define REG_PC uregs[15]
#define REG_NR uregs[7]
#define REG_RET uregs[0]
#define REG_ARG1 uregs[0]
#define REG_ARG2 uregs[1]
#define REG_ARG3 uregs[2]
#define REG_ARG4 uregs[3]
#define REG_ARG5 uregs[4]
#define REG_ARG6 uregs[5]
static const char SYSCALL_INSN[] = {0x00, 0x00, 0x00, 0xef}; /* swi 0 */
static const char RET_INSN[] = {0x04, 0xf0, 0x9d, 0xe4}; /* pop {pc} */

#endif