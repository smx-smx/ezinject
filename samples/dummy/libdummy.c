#include <stdio.h>
#include <stdio.h>
#include <dlfcn.h>

#include "log.h"
#include "util.h"
#include "interface/if_hook.h"
#include "interface/cpu/if_sljit.h"

#include "ezinject_injcode.h"

LOG_SETUP(V_DBG);

/**
 * Sample function that demonstrates the use of sljit
 **/
void *sljit_build_sample(){
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

	sljit_code = sljit_generate_code(compiler) + compiler->executable_offset;
	if(!sljit_code){
		ERR("Unable to build JIT Code");
		return NULL;
	}

	if(compiler){
		sljit_free_compiler(compiler);
	}

	INFO("JIT code");
	hexdump(sljit_code, compiler->executable_size);

	return sljit_code;
}

typedef int(*testFunc_t)(int arg1, int arg2);

static testFunc_t pfnOrigTestFunc = NULL;
static testFunc_t sljitCode = NULL;

int myCustomFn(int arg1, int arg2){
	DBG("original arguments: %d, %d", arg1, arg2);

	// call the sljit code sample
	arg1 = sljitCode(arg1, arg2);
	arg2 = 0;

	DBG("calling original(%d,%d)", arg1, arg2);
	// call the original function
	int origRet = pfnOrigTestFunc(arg1, arg2);

	// modify original return
	int newReturn = origRet * 10;
	DBG("return: %d, give %d", origRet, newReturn);
	return newReturn;
}

void installHooks(){
	sljitCode = sljit_build_sample();

	void *self = dlopen(NULL, RTLD_LAZY);
	testFunc_t pfnTestFunc = dlsym(self, "func1");
	if(pfnTestFunc == NULL){
		return;
	}

	/**
	 * create a trampoline to call the original function once the hook is installed
	 * -1 enables automatic backup length detection (most relevant for arches with variable opcode size)
	 **/
	pfnOrigTestFunc = inj_backup_function(pfnTestFunc, NULL, -1);
	if(!pfnOrigTestFunc){
		ERR("Cannot build the payload!");
		return;
	}

	testFunc_t pfnReplacement = myCustomFn;

	// print the chain (original -> hook -> orig_trampoline)
	INFO("%p -> %p -> %p", pfnTestFunc, pfnReplacement, pfnOrigTestFunc);

	/**
	 * overwrite the original function entry with a jump to the replacement
	 **/
	inj_replace_function(pfnTestFunc, pfnReplacement);
}

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

void libdl_test(){
	void *self = dlopen(NULL, RTLD_LAZY | RTLD_NOLOAD);
	lprintf("self: %p\n", self);
}

int lib_main(int argc, char *argv[]){
	lputs("Hello World from main");
	for(int i=0; i<argc; i++){
		lprintf("argv[%d] = %s\n", i, argv[i]);
	}
	libdl_test();
	installHooks();
	return 0;
}
