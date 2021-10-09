/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#ifndef __EZINJECT_AARCH64_H
#define __EZINJECT_AARCH64_H

#define REG_PC pc
#define REG_SP sp

#define REG(u, r) (u).r

#define EMIT_LDP(var1, var2) asm volatile("ldp %0, %1, [sp], #16" : "=r"(var1), "=r"(var2))

#define POP_PARAMS(out_br, out_func) \
	EMIT_LDP(out_br, out_func);

#define JMP_INSN "b"

typedef struct user_pt_regs regs_t;

#endif
