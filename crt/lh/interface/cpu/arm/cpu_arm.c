#include "interface/if_cpu.h"

inline int inj_opcode_bytes(){
	return 4;
}

inline int inj_absjmp_opcode_bytes() {
	return inj_opcode_bytes() * 2;
}

inline int inj_reljmp_opcode_bytes() {
	return inj_opcode_bytes();
}

int inj_build_rel_jump(uint8_t *buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address) {
	if (jump_destination % 4 != 0) {
		LH_ERROR("Destination address is not multiple of 4");
		return -1;
	}
	if (jump_opcode_address % 4 != 0) {
		LH_ERROR("Opcode address is not multiple of 4");
		return -1;
	}

	uint32_t offset = (uint32_t) jump_destination - jump_opcode_address - 4;
	LOG(4, "Offset is: " LX, offset);
	uint32_t operand = (offset / 4) - 1;
	LOG(4, "Operand is: " LX, operand);

/*
// todo: validate this somehow
  if((operand & 0xFF000000) > 0) {
     LH_ERROR("Jump is too big");
     return -1;
  }
*/
	uint32_t *x = (uint32_t *) buffer;
	*x = operand;
	buffer[3] = 0xEA;

	return LH_SUCCESS;
}

//ldr pc, [pc, #-4] => 04 f0 1f e5
int inj_build_abs_jump(uint8_t *buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address) {
	int i = 0;
	buffer[i++] = 0x04;
	buffer[i++] = 0xf0;
	buffer[i++] = 0x1f;
	buffer[i++] = 0xe5;

	uint32_t dest = (uint32_t) jump_destination;
	uint32_t *x = (uint32_t *) & (buffer[i]);
	*x = dest;

	return 0;
}
