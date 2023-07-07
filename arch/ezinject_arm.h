/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#ifndef __EZINJECT_ARM_H
#define __EZINJECT_ARM_H

#include "config.h"

#define REG_PC uregs[15]
#define REG_SP uregs[13]

#define REG(u, r) (u).regs.r

#ifdef USE_ARM_THUMB
#define EMIT_POP(var) \
	asm volatile( \
		"ldr %0, [sp]\n" \
		"add sp, sp, #4" \
	: "=r"(var));
#else
#define EMIT_POP(var) asm volatile("ldr %0, [sp], #4" : "=r"(var))
#endif


#define POP_PARAMS(out_br, out_func) \
	EMIT_POP(out_br); \
	EMIT_POP(out_func)

#define JMP_INSN "b"

typedef struct user regs_t;

#endif
