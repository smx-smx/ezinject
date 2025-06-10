/*
 * Copyright (C) 2025 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#ifndef __EZINJECT_HPPA_H
#define __EZINJECT_HPPA_H

// from <sys/uncontext.h>
#ifdef REG_PC
#undef REG_PC
#endif
#ifdef REG_SP
#undef REG_SP
#endif

//#define REG_PC1 iaoq[1]
//#define REG_PC iaoq[0]

// the kernel actually restores IAOQ from r31
#define REG_PC gr[31]
#define REG_SP gr[30]

#define REG(u, r) (u).r

// stack grows up
#define STACK_DIR 1

// since stack grows up, we must first subtract, then read
#define EMIT_POP(var) \
    asm volatile( \
        "ldw,mb %1(%%r30), %0\n" \
        : "=r"(var) : "i"(-sizeof(void *)))

#define POP_PARAMS(out_br, out_func) \
    EMIT_POP(out_br); \
    EMIT_POP(out_func)

#define JMP_INSN "b"

typedef struct user_regs_struct regs_t;

/**
 * Space reserved for the Frame Maker and the arguments
 * of the following functions
 * thanks to https://phrack.org/issues/58/11
 */
#define ADJUST_STACK() \
	asm volatile("ldo 64(%sp), %sp\n")
#endif