#include "interface/if_cpu.h"
#include "interface/if_inject.h"

inline int inj_opcode_bytes(){
	return -1;
}

inline int inj_reljmp_opcode_bytes() {
	return 5;
}

inline int inj_absjmp_opcode_bytes() {
	return 5 + 1;
}

int inj_build_rel_jump(uint8_t *buffer, uintptr_t jump_destination, uintptr_t source) {
	uintptr_t operand = jump_destination - source - 5;

	LOG(4, "REL JUMP (X64) TO " LX " FROM " LX " IS: " LX, jump_destination, source, operand);

	uint32_t lo = (uint32_t) (operand);

	buffer[0] = 0xE9;
	uint32_t *x = (uint32_t *) & (buffer[1]);
	*x = lo;
// 0:   e9 44 33 22 11          jmpq   0x11223349

	return LH_SUCCESS;
}

int inj_build_abs_jump(uint8_t *buffer, uintptr_t jump_destination, uintptr_t source) {
	uint32_t lo = (uint32_t) jump_destination;

	int i = 0;
	buffer[i++] = 0x68;
	uint32_t *x = (uint32_t *) & (buffer[i]);
	*x = lo;
	i += sizeof(uint32_t);
// 0: 68 44 33 22 11    push $11223344

	buffer[i++] = 0xC3;
//5: c3                retq

	return LH_SUCCESS;
}
