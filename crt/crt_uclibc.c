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
	void *ptrPage = PAGEALIGN(pfnInitializer);
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