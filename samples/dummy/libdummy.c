#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "config.h"
#include "log.h"
#include "interface/if_hook.h"
#include "interface/cpu/if_sljit.h"

#include "ezinject_util.h"
#include "ezinject_injcode.h"

LOG_SETUP(V_DBG);

// $TODO
#ifndef EZ_TARGET_WINDOWS
#define USE_SLJIT
#define USE_LH
#endif

#ifdef USE_SLJIT
/**
 * Sample function that demonstrates the use of sljit
 **/
void *sljit_build_sample(void **ppCodeMem){
	void *sljit_code = NULL;
	struct sljit_compiler *compiler = sljit_create_compiler(NULL);
	if(!compiler){
		ERR("Unable to create sljit compiler instance");
		return NULL;
	}

	/** Simple routine that returns 1337 **/
	sljit_emit_enter(compiler, 0, 0, 0, 0, 0, 0, 0);
	sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_RETURN_REG, 0, SLJIT_IMM, 1337);
	sljit_emit_return(compiler, SLJIT_MOV, SLJIT_RETURN_REG, 1337);

	sljit_code = sljit_generate_code(compiler);
	if(sljit_code == NULL){
		ERR("Unable to build JIT Code");
		return NULL;
	}
	if(ppCodeMem != NULL){
		*ppCodeMem = sljit_code;
	}
	sljit_code += compiler->executable_offset;	

	if(compiler){
		sljit_free_compiler(compiler);
	}

	INFO("JIT code");
	hexdump(sljit_code, compiler->executable_size);

	return sljit_code;
}
#endif

typedef int(*testFunc_t)(int arg1, int arg2);

static testFunc_t pfnOrigTestFunc = NULL;
static testFunc_t sljitCode = NULL;

#ifdef UCLIBC_OLD
int myCustomFn(int arg1, int arg2){
	UNUSED(arg1);
	UNUSED(arg2);
	return 1338;
}
#else
int myCustomFn(int arg1, int arg2){
	DBG("original arguments: %d, %d", arg1, arg2);

	#ifdef USE_SLJIT
	// call the sljit code sample
	arg1 = sljitCode(arg1, arg2);
	#endif

	arg2 = 0;

	DBG("calling original(%d,%d)", arg1, arg2);
	// call the original function
	int origRet = pfnOrigTestFunc(arg1, arg2);

	// modify original return
	int newReturn = origRet * 10;
	DBG("return: %d, give %d", origRet, newReturn);
	return newReturn;
}
#endif

#ifdef USE_LH
void installHooks(){
	void *self = dlopen(NULL, RTLD_LAZY);
	if(self == NULL){
		ERR("dlopen failed: %s", dlerror());
		return;
	}

	void *codeMem = NULL;
	int error = 1;

	do {
		testFunc_t pfnTestFunc = dlsym(self, "func1");
		if(pfnTestFunc == NULL){
			ERR("Couldn't locate test function: %s", dlerror());
			break;
		}

		#ifdef USE_SLJIT
		sljitCode = sljit_build_sample(&codeMem);
		#endif

		/**
		 * create a trampoline to call the original function once the hook is installed
		 * -1 enables automatic backup length detection (most relevant for arches with variable opcode size)
		 **/
		pfnOrigTestFunc = inj_backup_function(pfnTestFunc, NULL, -1);
		if(!pfnOrigTestFunc){
			ERR("Cannot build the payload!");
			break;
		}

		testFunc_t pfnReplacement = myCustomFn;

		// print the chain (original -> hook -> orig_trampoline)
		INFO("%p -> %p -> %p", pfnTestFunc, pfnReplacement, pfnOrigTestFunc);

		/**
		 * overwrite the original function entry with a jump to the replacement
		 **/
		inj_replace_function(pfnTestFunc, pfnReplacement);
		error = 0;
	} while(0);

	if(error){
		INFO("failed to install hooks");
		#ifdef USE_SLJIT
		if(codeMem != NULL){
			sljit_free_exec(codeMem);
		}
		#endif
		dlclose(self);
	} else {
		INFO("hooks installed succesfully");
	}
}
#endif

int lib_preinit(struct injcode_user *user){
	/**
	 * this is needed for hooks pointing to code in this library
	 * if we don't set this, dlclose() will be called and the hooks will segfault when called
	 * (because they will then refer to unmapped memory)
	 * this is *NOT* needed for code allocated elsewhere, e.g. on the heap (sljit)
	 **/
	user->persist = 1;
	return 0;
}

int lib_main(int argc, char *argv[]){
	lputs("Hello World from main");
	for(int i=0; i<argc; i++){
		lprintf("argv[%d] = %s\n", i, argv[i]);
	}
	#ifdef USE_LH
	installHooks();
	#endif
return 0;
}
