#include <stdio.h>
#include <stdio.h>
#include <dlfcn.h>
#include "log.h"
#include "util.h"
#include "interface/if_hook.h"
#include "interface/cpu/if_sljit.h"
#include "ezinject_injcode.h"

#define UNUSED(x) (void)(x)

enum verbosity_level verbosity = V_DBG;

void (*original_test_function) (int a, char *b);

lh_hook_t hook_settings = {
	.version = 1,
	.fn_hooks =
	{
		{
			.hook_kind = LHM_FN_HOOK_BY_NAME,
			.libname = "",
			.symname = "return1",
			.hook_fn = (uintptr_t) 0,
			.orig_function_ptr = (uintptr_t) & original_test_function, //save the original function address to "original_test_function"
		},
		{
			.hook_kind = LHM_FN_HOOK_TRAILING
		}
	}
};

void installHooks(){
	void *sljit_code = NULL;
	struct sljit_compiler *compiler = NULL;

	/* Uncomment to call the original */
	/*
	void (*f)(int, char*) = (void (*)(int a, char *b))original_test_function;
	f(1, "test");
	*/

	void *self = dlopen(NULL, RTLD_NOW);
	original_test_function = dlsym(self, "return1");

	void *origCode = inj_backup_function(
		&(hook_settings.fn_hooks[1]),
		(void *)original_test_function,
		NULL
	);
	if(!origCode){
		ERR("Cannot build the payload!");
		return;
	}

	compiler = sljit_create_compiler(NULL);
	if(!compiler){
		ERR("Unable to create sljit compiler instance");
		return;
	}

	/*
		Simple routine that returns 1337
	*/
	#if 0
	sljit_emit_ijump(compiler, SLJIT_JUMP, SLJIT_IMM, (sljit_sw)origCode);
	#else
	sljit_emit_enter(compiler, 0, 0, 0, 0, 0, 0, 0);
	sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_RETURN_REG, 0, SLJIT_IMM, 1337);
	sljit_emit_return(compiler, SLJIT_MOV, SLJIT_RETURN_REG, 1337);
	#endif

	sljit_code = sljit_generate_code(compiler) + compiler->executable_offset;
	if(!sljit_code){
		ERR("Unable to build JIT Code");
	}

	if(compiler)
		sljit_free_compiler(compiler);

	INFO("JIT code");
	hexdump(sljit_code, compiler->executable_size);
	/* Set the code we just generated as the replacement */
	hook_settings.fn_hooks[1].hook_fn = (uintptr_t)sljit_code;
	INFO("Injecting to %p", original_test_function);

	inj_replace_function(&(hook_settings.fn_hooks[1]), (uintptr_t)original_test_function);
}

void lib_preinit(struct injcode_user *user){
	UNUSED(user);
	// access user data
}

int lib_main(int argc, char *argv[]){
	puts("Hello World from main");
	for(int i=0; i<argc; i++){
		printf("argv[%d] = %s\n", i, argv[i]);
	}
	installHooks();
	return 0;
}