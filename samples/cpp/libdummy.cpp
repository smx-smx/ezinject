#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <dlfcn.h>

#include <string>

extern "C" {
	#include "log.h"
	#include "ezinject_util.h"
	#include "interface/if_hook.h"
	#include "interface/cpu/if_sljit.h"

	#include "ezinject_injcode.h"
}

LOG_SETUP(V_DBG);

typedef int (*testFunc_t)(std::string& str);

static testFunc_t pfnOrigTestFunc = NULL;

int myCustomFn(std::string& str){
	DBG("original: %s", str.c_str());

	// call the original function
	std::string str1 = "Hooked, string1";
	std::string str2 = "Again , string2";
	pfnOrigTestFunc(str1);
	pfnOrigTestFunc(str2);

	// modify original return
	return 1337;
}

void installHooks(){
	void *self = dlopen(NULL, RTLD_LAZY);
	if(self == NULL){
		ERR("dlopen failed: %s", dlerror());
		return;
	}

	void *codeMem = NULL;
	int error = 1;

	do {
		testFunc_t pfnTestFunc = (testFunc_t)dlsym(self, "func1");
		if(pfnTestFunc == NULL){
			ERR("Couldn't locate test function");
			break;
		}

		/**
		 * create a trampoline to call the original function once the hook is installed
		 * -1 enables automatic backup length detection (most relevant for arches with variable opcode size)
		 **/
		pfnOrigTestFunc = (testFunc_t)inj_backup_function((void *)pfnTestFunc, NULL, -1);
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
		inj_replace_function((void *)pfnTestFunc, (void *)pfnReplacement);
		error = 0;
	} while(0);

	if(error){
		INFO("failed to install hooks");
		if(codeMem != NULL){
			sljit_free_exec(codeMem);
		}
		dlclose(self);
	} else {
		INFO("hooks installed succesfully");
	}
}

extern "C" {
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
		installHooks();
		return 0;
	}
}