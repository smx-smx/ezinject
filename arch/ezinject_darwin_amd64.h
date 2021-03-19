#ifndef __EZINJECT_DARWIN_AMD64_H
#define __EZINJECT_DARWIN_AMD64_H

#include <mach/thread_status.h>

#define _CONCAT(x,y) x##y
#define CONCAT(x,y) _CONCAT(x,y)
#define REG(u, reg) (u).CONCAT(__,reg)

#define REG_PC rip
#define REG_SP rsp

#define EMIT_POP(var) asm volatile("pop %0" : "=r"(var))

#define POP_PARAMS(out_br, out_func) \
	EMIT_POP(out_br); \
	EMIT_POP(out_func)

#define JMP_INSN "jmp"

typedef x86_thread_state64_t regs_t;

#undef MACHINE_THREAD_STATE
#undef MACHINE_THREAD_STATE_COUNT
#define MACHINE_THREAD_STATE x86_THREAD_STATE64
#define MACHINE_THREAD_STATE_COUNT x86_THREAD_STATE64_COUNT

#endif