#ifndef __EZINJECT_ARCH_I386
#define __EZINJECT_ARCH_I386

#define REG_PC eip
#define REG_NR eax
#define REG_RET eax
#define REG_ARG1 ebx
#define REG_ARG2 ecx
#define REG_ARG3 edx
#define REG_ARG4 esi
#define REG_ARG5 edi
#define REG_ARG6 ebp
static const char SYSCALL_INSN[] = {0xcd, 0x80}; /* int 0x80 */
static const char RET_INSN[] = {0xc3}; /* ret */

#endif