#include "interface/if_hook.h"
#include "interface/if_cpu.h"
#include "interface/cpu/intel/cpu_intel.h"
#include "log.h"

#ifdef __FreeBSD__
#include <x86/reg.h>
#endif

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

int inj_build_rel_jump(uint8_t *buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address) {
	uintptr_t operand = jump_destination - jump_opcode_address - 5;

	LOG(4, "REL JUMP (X64) TO " LX " FROM " LX " IS: " LX, jump_destination, jump_opcode_address, operand);

	uint32_t lo = operand & 0xFFFFFFFF;
	uint32_t hi = ((operand >> 32) & 0xFFFFFFFF);
	if ((hi != 0) && (hi != 0xFFFFFFFF)) {
		LOG(4, "ERROR: high byte is %u, cant build reljump", hi);
		return -1;
	}

	buffer[0] = 0xE9;
	uint32_t *x = (uint32_t *) & (buffer[1]);
	*x = lo;
// 0:   e9 44 33 22 11          jmpq   0x11223349

	return 0;
}

int inj_build_abs_jump(uint8_t *buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address) {
	uint32_t lo = jump_destination & 0xFFFFFFFF;
	uint32_t hi = ((jump_destination >> 32) & 0xFFFFFFFF);

	int i = 0;
	buffer[i++] = 0x68;
	uint32_t *x = (uint32_t *) & (buffer[i]);
// 0: 68 44 33 22 11    push $11223344

	*x = lo;
	i += sizeof(uint32_t);
	buffer[i++] = 0xC7;
	buffer[i++] = 0x44;
	buffer[i++] = 0x24;
	buffer[i++] = 0x04;
	x = (uint32_t *) & (buffer[i]);
	*x = hi;
	i += sizeof(uint32_t);
// 5: c7 44 24 04 88 77 66 55    mov 4(%rsp), 55667788  # upper 4 bytes

	buffer[i++] = 0xC3;
//d: c3                retq

	return 0;
}

int inj_pass_args2func(pid_t pid, struct user *iregs, uintptr_t fn, uintptr_t arg1, uintptr_t arg2) {
	LOG(3, "function address is: 0x" LX, fn);
	iregs->regs.rsi = arg2;
	iregs->regs.rdi = arg1;
	lh_rset_ip(iregs, fn);
	lh_rset_ax(iregs, 0);

	return 0;
}

inline void lh_rset_ip(struct user *r, uintptr_t value) {
	r->regs.rip = value;
}

inline uintptr_t lh_rget_ip(struct user *r) {
	return r->regs.rip;
}

inline void lh_rset_sp(struct user *r, uintptr_t value) {
	r->regs.rsp = value;
}

inline uintptr_t lh_rget_sp(struct user *r) {
	return r->regs.rsp;
}

inline void lh_rset_fp(struct user *r, uintptr_t value) {
	r->regs.rbp = value;
}

inline uintptr_t lh_rget_fp(struct user *r) {
	return r->regs.rbp;
}

inline void lh_rset_ax(struct user *r, uintptr_t value) {
	r->regs.rax = value;
}

inline uintptr_t lh_rget_ax(struct user *r) {
	return r->regs.rax;
}
inline int lh_redzone() {
	return 128;
}

void lh_dump_regs(struct user *r) {
	LOG(3, "--------------------------- x86_64");
	LOG(3, "%%rip : 0x" LX, r->regs.rip);
	LOG(3, "%%rax : 0x" LX, r->regs.rax);
	LOG(3, "%%rbx : 0x" LX, r->regs.rbx);
	LOG(3, "%%rcx : 0x" LX, r->regs.rcx);
	LOG(3, "%%rdx : 0x" LX, r->regs.rdx);
	LOG(3, "%%rsi : 0x" LX, r->regs.rsi);
	LOG(3, "%%rdi : 0x" LX, r->regs.rdi);
	LOG(3, "%%rbp : 0x" LX, r->regs.rbp);
#ifndef __FreeBSD__
	LOG(3, "%%orax: 0x" LX, r->regs.orig_rax);
#endif
	LOG(3, "%%rsp : 0x" LX, r->regs.rsp);
}
//------------------------------------------ x86 end
