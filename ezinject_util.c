/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#include "dlfcn_compat.h"
#include "ezinject.h"
#include "ezinject_util.h"

void *code_data(void *code, enum code_data_transform type){
#if defined(EZ_ARCH_ARM) && defined(USE_ARM_THUMB)
	if(type == CODE_DATA_BYTES){
		return (void *)(UPTR(code) & ~1);
	}
#elif defined(EZ_ARCH_HPPA)
	if(type == CODE_DATA_BYTES || type == CODE_DATA_DEREF || type == CODE_DATA_DPTR){
		uintptr_t r22 = (uintptr_t)code;
		if ((uintptr_t)r22 & 2) {
			printf("%p -> ", code);
			if(type == CODE_DATA_DPTR){
				code = *(void **)(r22 + 2);
			} else {
				code = *(void **)(r22 - 2);
			}
			printf("%p\n", code);
		}
	}
#endif
	return code;
}

ez_addr sym_addr(void *handle, const char *sym_name, ez_addr lib){
	uintptr_t sym_addr = (uintptr_t)LIB_GETSYM(handle, sym_name);
	ez_addr sym = {
		.local = sym_addr,
		.remote = (sym_addr == 0) ? 0 : EZ_REMOTE(lib, sym_addr)
	};
	return sym;
}

void hexdump(void *pAddressIn, long lSize) {
	char szBuf[100];
	long lIndent = 1;
	long lOutLen, lIndex, lIndex2, lOutLen2;
	long lRelPos;
	struct {
		char *pData;
		unsigned long lSize;
	} buf;
	unsigned char *pTmp, ucTmp;
	unsigned char *pAddress = (unsigned char *)pAddressIn;

	buf.pData = (char *)pAddress;
	buf.lSize = lSize;

	while (buf.lSize > 0) {
		pTmp = (unsigned char *)buf.pData;
		lOutLen = (int)buf.lSize;
		if (lOutLen > 16)
			lOutLen = 16;

		// create a 64-character formatted output line:
		sprintf(szBuf, " >                                                      %"PRIX32, (uint32_t)(pTmp - pAddress));
		lOutLen2 = lOutLen;

		for (lIndex = 1 + lIndent, lIndex2 = 53 - 15 + lIndent, lRelPos = 0; lOutLen2; lOutLen2--, lIndex += 2, lIndex2++) {
			ucTmp = *pTmp++;
			sprintf(szBuf + lIndex, "%02X ", (unsigned short)ucTmp);
			if (!isprint(ucTmp))
				ucTmp = '.';	// nonprintable char
			szBuf[lIndex2] = ucTmp;

			if (!(++lRelPos & 3)) {	// extra blank after 4 bytes
				lIndex++;
				szBuf[lIndex + 2] = ' ';
			}
		}
		if (!(lRelPos & 3))
			lIndex--;
		szBuf[lIndex] = '<';
		szBuf[lIndex + 1] = ' ';
		printf("%s\n", szBuf);
		buf.pData += lOutLen;
		buf.lSize -= lOutLen;
	}
}
