#include <stdint.h>
#include "interface/if_cpu.h"
#include "interface/cpu/cpu_common.h"
#include "log.h"

#include "ezinject_common.h"

inline int inj_opcode_bytes(){
	return 4;
}

inline int inj_absjmp_opcode_bytes() {
	return inj_opcode_bytes() * 4;
}

inline int inj_reljmp_opcode_bytes() {
	return inj_opcode_bytes();
}

#define SIZED(x, nbits) (x & ((1 << nbits) - 1))

#define OP_SHIFT (32 - 6)
#define RS_SHIFT (OP_SHIFT - 5)
#define RT_SHIFT (RS_SHIFT - 5)
#define IMM_SHIFT (RT_SHIFT - 16)
#define RD_SHIFT (RT_SHIFT - 5)
#define SHAMT_SHIFT (RD_SHIFT - 5)
#define FUNC_SHIFT (SHAMT_SHIFT - 6)
#define TARGET_SHIFT (OP_SHIFT - 26)

#define OP_FIELD(op) (SIZED(op, 6) << OP_SHIFT)
#define RS_FIELD(rs) (SIZED(rs, 5) << RS_SHIFT)
#define RT_FIELD(rt) (SIZED(rt, 5) << RT_SHIFT)
#define RD_FIELD(rd) (SIZED(rd, 5) << RD_SHIFT)
#define SHAMT_FIELD(shamt) (SIZED(shamt, 5) << SHAMT_SHIFT)
#define FUNC_FIELD(func) (SIZED(func, 6) << FUNC_SHIFT)
#define IMM_FIELD(imm) (SIZED(imm, 16) << IMM_SHIFT)
#define TARGET_FIELD(tgt) (SIZED(tgt, 26) << TARGET_SHIFT)

#define OP_R(op, rs, rt, rd, shamt, func) \
	OP_FIELD(op) | \
	RS_FIELD(rs) | \
	RT_FIELD(rt) | \
	SHAMT_FIELD(shamt) | \
	FUNC_FIELD(func)

#define OP_I(op, rs, rt, imm) \
	OP_FIELD(op) | \
	RS_FIELD(rs) | \
	RT_FIELD(rt) | \
	IMM_FIELD(imm)

#define OP_J(op, target) \
	OP_FIELD(op) | \
	TARGET_FIELD(target)

#define OPCD_ADDI 0
#define FUNC_ADDI 32

#define OPCD_J  2
#define OPCD_ORI 13
#define OPCD_LUI 15
#define OPCD_LW 35
#define OPCD_SW 43

#define OPCD_JR 0
#define FUNC_JR 8

#define REG_ZERO 0
#define REG_AT 1
#define REG_T0 8
#define REG_SP 29

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

	uint32_t jmp = OP_J(OPCD_J, operand);
	WRITE32(buffer, jmp);
	return 0;
}

int inj_build_abs_jump(uint8_t *buffer, void *jump_destination, void *jump_opcode_address) {
	UNUSED(jump_opcode_address);
	
	uintptr_t target = (uintptr_t)jump_destination;

	/** FIXME: this clobbers ($at) **/
	// set dst addr
	uint16_t high = (uint16_t)(target >> 16);
	uint16_t low  = (uint16_t)target;
	WRITE32(buffer, OP_I(OPCD_LUI, REG_ZERO, REG_AT, high));
	WRITE32(buffer, OP_I(OPCD_ORI, REG_AT, REG_AT, low));
	// write jmp
	WRITE32(buffer, OP_R(OPCD_JR, REG_AT, REG_ZERO, REG_ZERO, 0, FUNC_JR));
	// delay slot
	WRITE32(buffer, 0);
	return 0;
}