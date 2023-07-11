/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include "interface/if_cpu.h"
#include "interface/if_hook.h"
#include "interface/cpu/cpu_common.h"
#include "log.h"

#include "ezinject_common.h"

inline int inj_opcode_bytes(){
	return -1;
}

inline int inj_reljmp_opcode_bytes() {
	return 5;
}

inline int inj_absjmp_opcode_bytes() {
	return 5 + 1;
}

/** $TODO: untested **/
int inj_build_rel_jump(uint8_t *buffer, void *jump_destination, void *source) {
	uintptr_t operand = PTRDIFF(jump_destination, source) - 5;

	LOG(4, "REL JUMP (X64) TO %p FROM %p IS: " LX, jump_destination, source, operand);

	uint32_t lo = (uint32_t) (operand);

// 0:   e9 44 33 22 11          jmpq   0x11223349
	WRITE8(buffer, 0xE9);
	WRITE32(buffer, lo);
	return 0;
}

int inj_build_abs_jump(uint8_t *buffer, void *jump_destination, void *source) {
	uint32_t lo = (uint32_t) jump_destination;

// 0: 68 44 33 22 11    push $11223344
	WRITE8(buffer, 0x68);
	WRITE32(buffer, lo);

//5: c3                retq
	WRITE8(buffer, 0xC3);
	return 0;
}
