#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>

#include "log.h"

#include "interface/if_cpu.h"
#include "interface/if_hook.h"

int unprotect(void *addr) {
	// Move the pointer to the page boundary
	int page_size = getpagesize();
	addr -= (unsigned long)addr % page_size;

	if(mprotect(addr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
		PERROR("mprotect");
	    return -1;
	}

	return 0;
}

int inj_replace_function(void *original_fn, void *replacement_fn){
	size_t jumpSz;
	// Calculate the JUMP from Original to Replacement, so we can get the minimum size to save
	// We need this to avoid opcode overlapping (especially on Intel, where we can have variable opcode size)
	uint8_t *replacement_jump;	//original -> custom
	if(!(replacement_jump = inj_build_jump(replacement_fn, 0, &jumpSz)))
		return -1;

	if( unprotect(original_fn) < 0)
			return -1;

	memcpy(original_fn, replacement_jump, jumpSz);
	return 0;
}