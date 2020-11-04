#include <stdint.h>
#include "interface/if_cpu.h"
#include "interface/cpu/cpu_common.h"
#include "log.h"

#include "ezinject_common.h"

inline int inj_opcode_bytes(){
	return 4;
}

inline int inj_absjmp_opcode_bytes() {
	return inj_opcode_bytes() * 2;
}

inline int inj_reljmp_opcode_bytes() {
	return inj_opcode_bytes();
}

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

//ldr pc, [pc, #-4] => 04 f0 1f e5
int inj_build_abs_jump(uint8_t *buffer, void *jump_destination, void *jump_opcode_address) {
	WRITE32(buffer, 0xE51FF004);
	WRITE32(buffer, (uint32_t)jump_destination);
	return 0;
}
