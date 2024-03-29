/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <stdint.h>
#include "interface/if_cpu.h"
#include "interface/cpu/cpu_common.h"
#include "log.h"

#include "ezinject_common.h"

inline int inj_opcode_bytes(){
	return 4;
}

inline int inj_absjmp_opcode_bytes() {
	return inj_opcode_bytes() * 5;
}

inline int inj_reljmp_opcode_bytes() {
	return inj_opcode_bytes();
}

/** $TODO: untested **/
int inj_build_rel_jump(uint8_t *buffer, void *jump_destination, void *jump_opcode_address) {
	UNUSED(buffer);
	UNUSED(jump_destination);
	UNUSED(jump_opcode_address);
	return -1;
}

#define MOVZ_X16 0xd2800010
#define MOVK_X16 0xf2800010
#define BR_X16 0xd61f0200

int inj_build_abs_jump(uint8_t *buffer, void *jump_destination, void *jump_opcode_address) {
	UNUSED(jump_opcode_address);

	// wow! apparently we need 4 instructions to load a 64bit constant on aarch64
	// we also don't have access to the PC register to do a pop
	// additionally, the constants are encoded with rotations!
	// ...
	// d29f59d0        mov     x16, #0xface
 	// f2b7ddf0        movk    x16, #0xbeef, lsl #16
 	// f2dbd5b0        movk    x16, #0xdead, lsl #32
 	// f2fe01b0        movk    x16, #0xf00d, lsl #48

	// NOTE: the following trashes X16 (the linker scratch register)
	// so this code is unfortunately ABI dependent
	// the encoding of constants is adapted from sljit
	uintptr_t imm = (uintptr_t)jump_destination;
	WRITE32(buffer, MOVZ_X16 | ((imm & 0xffff) << 5));
	WRITE32(buffer, MOVK_X16 | (((imm >> 16) & 0xffff) << 5) | (1 << 21));
	WRITE32(buffer, MOVK_X16 | (((imm >> 32) & 0xffff) << 5) | (2 << 21));
	WRITE32(buffer, MOVK_X16 | ((imm >> 48) << 5) | (3 << 21));
	WRITE32(buffer, BR_X16);
	return 0;
}
