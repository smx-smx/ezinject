#ifndef __EZINJECT_AMD64_H
#define __EZINJECT_AMD64_H

#define REG_PC rip
#define REG_NR rax
#define REG_RET rax
#define REG_ARG1 rdi
#define REG_ARG2 rsi
#define REG_ARG3 rdx
#define REG_ARG4 r10
#define REG_ARG5 r8
#define REG_ARG6 r9
static const char SYSCALL_INSN[] = {0x0f, 0x05}; /* syscall */
static const char RET_INSN[] = {0xc3}; /* ret */

#endif