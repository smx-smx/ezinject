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