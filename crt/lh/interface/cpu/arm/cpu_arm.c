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

#include "config.h"
#include "log.h"

#include "ezinject_common.h"

inline int inj_opcode_bytes(){
	#ifdef USE_ARM_THUMB
	return -1;
	#else
	return 4;
	#endif
}

inline int inj_absjmp_opcode_bytes() {
	// ldr + addr (both ARM/THUMB)
	return 8;
}

inline int inj_reljmp_opcode_bytes() {
	#ifdef USE_ARM_THUMB
	// FIXME: unsupported
	return 0;
	#else
	return inj_opcode_bytes();
	#endif
}

/** $TODO: untested **/
int inj_build_rel_jump(uint8_t *buffer, void *jump_destination, void *jump_opcode_address) {
	if (UPTR(jump_destination) % 4 != 0) {
		ERR("Destination address is not multiple of 4");
		return -1;
	}
	if (UPTR(jump_opcode_address) % 4 != 0) {
		ERR("Opcode address is not multiple of 4");
		return -1;
	}

	uint32_t offset = (uint32_t) PTRDIFF(jump_destination, jump_opcode_address) - 4;
	LOG(4, "Offset is: " LX, offset);
	uint32_t operand = (offset / 4) - 1;
	LOG(4, "Operand is: " LX, operand);

/*
// todo: validate this somehow
  if((operand & 0xFF000000) > 0) {
     ERR("Jump is too big");
     return -1;
  }
*/
	uint32_t jmp = 0xEA | (operand >> 8);
	WRITE32(buffer, jmp);
	return 0;
}

int inj_build_abs_jump(uint8_t *buffer, void *jump_destination, void *jump_opcode_address) {
	// we want to store the following word onto the $pc register
	// on arm, PC is +8 at execution time, so need an offset of -4
	//   ARM   -> ldr pc, [pc, #-4] -> E5 1F F0 04
	// on thumb, PC is +4 at execution time, so we need no offset
	//   THUMB -> ldr pc, [pc]      -> F8 DF F0 00"

	if((uintptr_t)jump_opcode_address & 1){
		// thumb encoding
		WRITE16(buffer, 0xF8DF);
		WRITE16(buffer, 0xF000);
	} else {
		// arm encoding
		WRITE32(buffer, 0xE51FF004);
	}

	WRITE32(buffer, (uint32_t)jump_destination);
	return 0;
}
