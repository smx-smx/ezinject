/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include "config.h"
#include <unistd.h>
#include <sys/mman.h>

extern void ret_start(void);
extern void ret_end(void);

int ret(int dummy){
	if(dummy){
		EMIT_LABEL("ret_start");
		return 0;
	}
	// we also copy the remaining part of the dummy branch, but we don't care (since we're returning)
	EMIT_LABEL("ret_end");
	return 0;
}

void uclibc_fixup_pthread(){
	void *h_libpthread = dlopen(PTHREAD_LIBRARY_NAME, RTLD_LAZY | RTLD_NOLOAD);
	if(h_libpthread == NULL){
		PERROR("dlopen");
		return;
	}

	DBG("__pthread_initialize_minimal");
	void (*pfnInitializer)() = dlsym(h_libpthread, "__pthread_initialize_minimal");
	if(pfnInitializer != NULL){
		pfnInitializer();
	}

	// once we have initialized, overwrite the function with a return
	void *ptrPage = PAGEALIGN_DOWN(pfnInitializer);
	size_t pageSize = getpagesize();
	if(mprotect(ptrPage, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC) < 0){
		PERROR("mprotect");
		return;
	}
	hexdump(&ret_start, PTRDIFF(&ret_end, &ret_start));
	memcpy(ptrPage, &ret_start, PTRDIFF(&ret_end, &ret_start));
	if(mprotect(ptrPage, pageSize, PROT_READ | PROT_EXEC) < 0){
		PERROR("mprotect");
		return;
	}
}
