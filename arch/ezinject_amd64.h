#ifndef __EZINJECT_AMD64_H
#define __EZINJECT_AMD64_H

#define REG_PC rip
#define REG_SP rsp
#define REG_NR rax
#define REG_RET rax
#define REG_ARG1 rdi
#define REG_ARG2 rsi
#define REG_ARG3 rdx
#define REG_ARG4 r10
#define REG_ARG5 r8
#define REG_ARG6 r9

#define REG(u, r) (u).regs.r

#define EMIT_SC() asm volatile("syscall\n")
#define EMIT_POP(var) asm volatile("pop %0" : "=r"(var))

#endif