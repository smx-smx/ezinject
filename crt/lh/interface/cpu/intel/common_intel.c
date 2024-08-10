/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include "interface/cpu/intel/cpu_intel.h"
#include "interface/if_hook.h"
#include "log.h"
#include "ezinject_util.h"

/*
 * Relocates code pointed by codePtr from sourcePC to destPC
 */
int inj_relocate_code(void *codePtr, unsigned int codeSz, void *sourcePC, void *destPC){
#ifndef USE_CAPSTONE
	return 0;
#else
	csh handle;
	cs_insn *insns;
	size_t count;
	int result = 0;

	char pcRegName[4];
	#if __i386__
		strcpy((char *)&pcRegName, "eip");
		if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
			goto err_open;
	#elif __x86_64__
		strcpy((char *)&pcRegName, "rip");
		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
			goto err_open;
	#endif

	//Enable optional details
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	size_t i, j;

	count = cs_disasm(handle, codePtr, codeSz, (uint64_t)sourcePC, 0, &insns);
	if((ssize_t)count < 0)
		goto err_disasm;

	off_t curPos = 0;
	for (i = 0; i < count; i++) {
		cs_insn *insn = &(insns[i]);
		printf("0x"LLX":\t%s\t\t%s\n", insn->address, insn->mnemonic, insn->op_str);
		cs_detail *detail = insn->detail;

		for(j=0; j<detail->x86.op_count; j++){
			cs_x86_op *op = &(detail->x86.operands[j]);
			switch(op->type) {
				case X86_OP_REG:
					printf("\t\toperands[%"PRIuMAX"].type: REG = %s\n", j, cs_reg_name(handle, op->reg));
					break;
				case X86_OP_MEM:
					printf("\t\toperands[%"PRIuMAX"].type: MEM\n", j);
					if (op->mem.base != X86_REG_INVALID){
						const char *reg_name = cs_reg_name(handle, op->mem.base);
						printf("\t\t\toperands[%"PRIuMAX"].mem.base: REG = %s\n", j, reg_name);
						if(!strcmp(reg_name, (char *)&pcRegName)){
							//apparently works for cmp, lea, anything mem relative hopefully
							//if(!strcmp(insn->mnemonic, "cmp")){
								unsigned displacement = (sourcePC + insn->size) - destPC;
								if(verbosity >= 3){
									LOG(3, ">> New Displacement: %u", displacement);
									DBG("instruction before");
									hexdump(insn->bytes, insn->size);
								}
								printf(">> Relocating RELATIVE CMP MEM ACCESS...\n");
								*(unsigned *)(codePtr + curPos + 3) = displacement & 0xFFFFFFFFFF;
								if(verbosity >= 3){
									DBG("instruction after");
									hexdump(codePtr + curPos, insn->size);
								}
							//}
						}
					}
					if (op->mem.index != X86_REG_INVALID){
						printf("\t\t\toperands[%"PRIuMAX"].mem.index: REG = %s\n", j, cs_reg_name(handle, op->mem.index));
					}
					if (op->mem.disp != 0){
						printf("\t\t\toperands[%"PRIuMAX"].mem.disp: 0x%"PRIxPTR"\n", j, op->mem.disp);
					}
					break;
				case X86_OP_IMM:
					printf("\t\toperands[%"PRIdMAX"].type: IMM = 0x%"PRIxPTR"\n", j, op->imm);
					break;
				case X86_OP_INVALID:
				default:
					break;
			}
		}

		curPos += insn->size;
	}
	goto ret;
	ret:
		cs_free(insns, count);
		return result;

	err_open:
		ERR("cs_open failed!");
		return -1;
	err_disasm:
		ERR("cs_disasm failed!");
		cs_close(&handle);
		return -1;
#endif
}
