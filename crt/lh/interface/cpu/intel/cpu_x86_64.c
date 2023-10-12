/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include "interface/if_hook.h"
#include "interface/if_cpu.h"
#include "interface/cpu/intel/cpu_intel.h"
#include "interface/cpu/cpu_common.h"
#include "log.h"

#ifdef __FreeBSD__
#include <x86/reg.h>
#endif

#include "ezinject_common.h"

//------------------------------------------ x86 begin
inline int inj_opcode_bytes(){
	return -1;
}

inline int inj_reljmp_opcode_bytes() {
	return 5;
}

inline int inj_absjmp_opcode_bytes() {
	return
		5 + //push
		8 + //mov
		1; //ret
}

/** $TODO: untested **/
int inj_build_rel_jump(uint8_t *buffer, void *jump_destination, void *jump_opcode_address) {
	uintptr_t operand = PTRDIFF(jump_destination, jump_opcode_address) - 5;
	LOG(4, "REL JUMP (X64) TO %p FROM %p IS: " LX, jump_destination, jump_opcode_address, operand);

	uint32_t lo = operand & 0xFFFFFFFF;
	uint32_t hi = ((operand >> 32) & 0xFFFFFFFF);
	if ((hi != 0) && (hi != 0xFFFFFFFF)) {
		LOG(4, "ERROR: high byte is %u, cant build reljump", hi);
		return -1;
	}

// 0:   e9 44 33 22 11          jmpq   0x11223349
	WRITE8(buffer, 0xE9);
	WRITE32(buffer, lo);
	return 0;
}

int inj_build_abs_jump(uint8_t *buffer, void *jump_destination, void *jump_opcode_address) {
	UNUSED(jump_opcode_address);

	uint64_t target = (uint64_t)jump_destination;

	uint32_t lo = target & 0xFFFFFFFF;
	uint32_t hi = ((target >> 32) & 0xFFFFFFFF);

	// 0: 68 44 33 22 11    push $11223344
	WRITE8(buffer, 0x68);
	WRITE32(buffer, lo);

	// 5: c7 44 24 04 88 77 66 55    mov 4(%rsp), 55667788  # upper 4 bytes
	WRITE32(buffer, 0x042444C7);
	WRITE32(buffer, hi);

	//d: c3                retq
	WRITE8(buffer, 0xC3);
	return 0;
}
