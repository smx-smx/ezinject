/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#ifndef __EZINJECT_ARCH_I386
#define __EZINJECT_ARCH_I386

#include <machine/reg.h>

#define _CONCAT(x,y) x##y
#define CONCAT(x,y) _CONCAT(x,y)

#define REG_PC eip
#define REG_SP esp

#define REG(u, reg) (u).CONCAT(r_,reg)

#define EMIT_POP(var) asm volatile("pop %0" : "=r"(var))

#define POP_PARAMS(out_br, out_func) \
	EMIT_POP(out_func); \
	EMIT_POP(out_br)

#define JMP_INSN "jmp"

typedef struct reg regs_t;

#endif
