/*
 * Copyright (C) 2025 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#ifndef __EZINJECT_PPC_H
#define __EZINJECT_PPC_H

#define REG_PC nip
#define REG_SP gpr[1]
#define REG_TOC gpr[2]

#define REG(u, r) (u).regs.r

#define EMIT_POP(var) \
	asm volatile( \
		"lwz %0, 0(%%r1)\n" \
		"addi %%r1, %%r1, 4\n" \
	: "=r"(var));

#define POP_PARAMS(out_br, out_func) \
	EMIT_POP(out_func); \
	EMIT_POP(out_br)

/**
 * reserve space for:
 * - back chain
 * - CR save
 * - reserved 
 * - LR save
 * - TOC pointer
 * there are different ABIs here.
 * the older PPC ABI uses 48 bytes, while the ELFv2 ABI uses 32 bytes
 * just use the worst case size to support both.
 */
#define ADJUST_STACK() \
	asm volatile("stwu 1, -48(1)");

#define JMP_INSN "b"

typedef struct user regs_t;


#endif