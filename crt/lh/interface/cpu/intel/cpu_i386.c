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
