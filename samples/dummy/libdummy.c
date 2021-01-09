#include <stdio.h>
#include <stdio.h>
#include <dlfcn.h>

#include "log.h"
#include "util.h"
#include "interface/if_hook.h"
#include "interface/cpu/if_sljit.h"

#include "ezinject_injcode.h"

LOG_SETUP(V_DBG);

int lib_main(int argc, char *argv[]);

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
	arg1 = sljitCode(arg1, arg2);
	arg2 = 0;

	DBG("calling original(%d,%d)", arg1, arg2);
	int origRet = pfnOrigTestFunc(arg1, arg2);
	int newReturn = origRet * 10;
	DBG("return: %d, give %d", origRet, newReturn);
	return newReturn;
}

void installHooks(){
	sljitCode = sljit_build_sample();

	void *self = dlopen(NULL, RTLD_NOW);
	testFunc_t pfnTestFunc = dlsym(self, "return1");

	pfnOrigTestFunc = inj_backup_function(pfnTestFunc, NULL, -1);
	if(!pfnOrigTestFunc){
		ERR("Cannot build the payload!");
		return;
	}

	testFunc_t pfnReplacement = myCustomFn;
	INFO("%p -> %p -> %p", pfnTestFunc, pfnReplacement, pfnOrigTestFunc);
	inj_replace_function(pfnTestFunc, pfnReplacement);
}

int lib_preinit(struct injcode_user *user){
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
