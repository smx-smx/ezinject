#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>

#include "lh_hook.h"
#include "log.h"

#include "interface/if_cpu.h"
#include "interface/if_hook.h"

/*
 * Creates and returns a new empty session (lh_session_t)
 */
lh_session_t *lh_alloc() {
	lh_session_t *re = (lh_session_t *) calloc(1, sizeof(lh_session_t));
	if (!re) {
		PERROR("malloc");
		return NULL;
	}
	return re;
}

/*
 * Frees a session object
 */
void lh_free(lh_session_t ** session) {
	if (session == NULL)
		return;

	lh_session_t *s = *session;
	if(!s){
		*session = NULL;
		return;
	}

	size_t i;
	if(s->exe_symbols){
		for(i=0; i<s->exe_symbols_num; i++){
			if(s->exe_symbols[i].name){
				free(s->exe_symbols[i].name);
			}
		}
		free(s->exe_symbols);
	}

	ld_free_maps(s->ld_maps, s->ld_maps_num);

	if(s->exe_interp.name){
		free(s->exe_interp.name);
	}

	free(s);

	*session = NULL;
}

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

int inj_replace_function(lh_fn_hook_t *fnh, uintptr_t symboladdr){
	size_t jumpSz;
	// Calculate the JUMP from Original to Replacement, so we can get the minimum size to save
	// We need this to avoid opcode overlapping (especially on Intel, where we can have variable opcode size)
	uint8_t *replacement_jump;	//original -> custom
	if(!(replacement_jump = inj_build_jump(fnh->hook_fn, 0, &jumpSz)))
		return -1;

	if( unprotect((void *)symboladdr) < 0)
			return -1;

	memcpy((void *)symboladdr, replacement_jump, jumpSz);
	return 0;
}

int lh_process_hooks(void *lib_handle){
	lh_session_t *lh = lh_alloc();
	if (lh == NULL) {
		return -1;
	}

	int rc = -1;
	do {
		bool oneshot = true;
		struct ld_procmaps *lib_to_hook = NULL;

		lh_hook_t *hook_settings = dlsym(lib_handle, "hook_settings");
		if (hook_settings == NULL) {
			ERR("Couldnt retrieve hook_settings symbol");
			break;
		}

		INFO("Hook settings found, v%d", hook_settings->version);

		// For future versions of the structure
		if (hook_settings->version != 1) {
			ERR("hook_settings version is not supported");
			break;
		}

		int hook_successful = 0;

		int fni = 0;
		lh_fn_hook_t *fnh = &(hook_settings->fn_hooks[0]);
		// For every hook definition
		while (1) {
			if (fnh->hook_kind == LHM_FN_HOOK_TRAILING){
				break;
			}

			hook_successful = 0;

			DBG("Function hook libname: '%s', symbol: '%s', offset: " LX, fnh->libname, fnh->symname, fnh->sym_offset);
			DBG("The replacement function: " LX, fnh->hook_fn);

			// Locate the library specified in the hook section (if any)
			if (ld_find_library(lh->ld_maps, lh->ld_maps_num, fnh->libname, false, &lib_to_hook) != 0) {
				ERR("Couldn't find the requested library in /proc/<pid>/maps");
				continue; //switch to the next hook
			}

			uintptr_t symboladdr = 0;

			switch(fnh->hook_kind){
				case LHM_FN_HOOK_BY_NAME:
					symboladdr = ld_find_address(lib_to_hook, fnh->symname, NULL);
					if(symboladdr == 0){
						ERR("Symbol not found, trying dlsym");
						void *lib_handle = dlopen(fnh->libname, RTLD_LAZY | RTLD_GLOBAL);
						if(!lib_handle){
							PERROR("dlopen");
							continue;
						}
						symboladdr = (uintptr_t)dlsym(lib_handle, fnh->symname);
						dlclose(lib_handle);
					}
					break;
				case LHM_FN_HOOK_BY_OFFSET:
					symboladdr = lib_to_hook->addr_begin + fnh->sym_offset;
					break;
				case LHM_FN_HOOK_BY_AOBSCAN:
					; //empty statement for C89
					size_t searchSz = fnh->aob_size;
					uint8_t *pattern = fnh->aob_pattern;
					if(!pattern){
						ERR("No AOB pattern from module!");
						continue;
					}

					uintptr_t idx;
					for(idx = lib_to_hook->addr_begin; idx < lib_to_hook->addr_end; idx++){
						uint8_t *rcode = (uint8_t *)idx;
						if(!memcmp(rcode, pattern, searchSz)){
							INFO("AOB SCAN SUCCEDED!");
							symboladdr = idx;
							break;
						}
					}
					break;
				default:
					ERR("Invalid Hook method Specified!");
					continue;
			}

			if (symboladdr == 0) {
				INFO("ERROR: hook_settings->fn_hooks[%d] was not found.", fni);
				continue;
			}
			INFO("'%s' resolved to "LX, fnh->symname, symboladdr);


			int do_hook = 1;
			if (!fnh->hook_fn) {
				INFO("WARNING: hook_settings->fn_hooks[%d], hook_fn is null", fni);
				/*
				 * We accept null replacements, if user just wants to save the function address.
				 * In that case, don't place the hook
				 */
				do_hook = 0;
				goto after_hook;
			}

			uintptr_t orig_code_addr = 0;
			size_t saved_bytes;
			if(do_hook){
				// Alloc memory (mmap) and prepare orig code + jump back
				// This is the new address of the original function
				void *orig_function;
				if((orig_function = inj_backup_function(fnh, (uint8_t *)symboladdr, &saved_bytes)) == NULL){
					ERR("Failed to build payload!");
					continue;
				}
				orig_code_addr = (uintptr_t)orig_function;

				// Enable the hook by copying the replacement jump to our new function
				if(inj_replace_function(fnh, symboladdr) < 0){
					ERR("Failed to copy replacement jump!");
					continue;
				}
			}

			after_hook:
				if (fnh->orig_function_ptr != 0) {
					uintptr_t func_addr = (do_hook) ? orig_code_addr : symboladdr;
					*(void **)(fnh->orig_function_ptr) = (void *)func_addr;
				}
				if (fnh->code_rest_ptr != 0) {
					uintptr_t func_addr = (do_hook) ? symboladdr + saved_bytes: symboladdr;
					*(void **)(fnh->code_rest_ptr) = (void *)func_addr;
				}

				oneshot = false;

				fni++;
				fnh++;
		}
	} while(0);

	lh_free(&lh);
	return rc;
}