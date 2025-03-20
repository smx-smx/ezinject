#include <stdio.h>
#include <stdlib.h>

#include "config.h"
#include "log.h"
#include "interface/if_hook.h"

#include "dlfcn_compat.h"
#include "ezinject_util.h"
#include "ezinject_injcode.h"

LOG_SETUP(V_DBG);

#ifdef USE_LH
typedef int(*testFunc_t)(int arg1, int arg2);

static testFunc_t pfnOrigTestFunc = NULL;

#ifdef UCLIBC_OLD
int myCustomFn(int arg1, int arg2){
	UNUSED(arg1);
	UNUSED(arg2);
	return 1338;
}
#else
int myCustomFn(int arg1, int arg2){
	DBG("original arguments: %d, %d", arg1, arg2);

	DBG("calling original(%d,%d)", arg1, arg2);
	// call the original function
	int origRet = pfnOrigTestFunc(arg1, arg2);

	// modify original return
	int newReturn = origRet * 10;
	DBG("return: %d, give %d", origRet, newReturn);
	return newReturn;
}
#endif

void installHooks(){
	#ifdef EZ_TARGET_WINDOWS
	void *self = GetModuleHandle(NULL);
	#else
	void *self = dlopen(NULL, RTLD_NOW);
	#endif
	if(self == NULL){
		ERR("dlopen failed: %s", LIB_ERROR());
		return;
	}

	int error = 1;

	do {
		#ifdef EZ_TARGET_WINDOWS
		testFunc_t pfnTestFunc = (testFunc_t) GetProcAddress(self, "func1");
		#else
		testFunc_t pfnTestFunc = dlsym(self, "func1");
		#endif
		if(pfnTestFunc == NULL){
			ERR("Couldn't locate test function: %s", LIB_ERROR());
			break;
		}

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
		#ifndef EZ_TARGET_WINDOWS
		dlclose(self);
		#endif
	} else {
		INFO("hooks installed succesfully");
	}
}
#endif

void printenv() {
    char ** env;
#if defined(EZ_TARGET_WINDOWS) && (_MSC_VER >= 1900)
    env = *__p__environ();
#elif defined(EZ_TARGET_FREEBSD)
	// workaround https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=265008
	char **environ = (char **)dlsym(RTLD_DEFAULT, "environ");
#else
    extern char ** environ;
    env = environ;
#endif
    for (; *env; ++env) {
        printf("%s\n", *env);
    }
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

int lib_main(int argc, char *argv[]){
	#ifdef EZ_TARGET_LINUX
	char cmd[128];
	sprintf(cmd, "cat /proc/%u/maps", getpid());
	system(cmd);
	#endif

	#ifdef EZ_TARGET_POSIX
	printenv();
	#endif

	lputs("Hello World from main");
	for(int i=0; i<argc; i++){
		lprintf("argv[%d] = %s\n", i, argv[i]);
	}

	#ifdef USE_LH
	installHooks();
	#endif
return 0;
}

#ifdef EZ_TARGET_WINDOWS
BOOL __stdcall DllMainCRTStartup(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved){
	return TRUE;
}

BOOL WINAPI DllEntryPoint(HINSTANCE hinstDLL, DWORD fdwReason,
LPVOID lpReserved){
	return TRUE;
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved )  // reserved
{
    // Perform actions based on the reason for calling.
    switch( fdwReason )
    {
        case DLL_PROCESS_ATTACH: // Initialize once for each new process.
         // Return FALSE to fail DLL load.
        	break;
        case DLL_THREAD_ATTACH: // Do thread-specific initialization.
            break;
        case DLL_THREAD_DETACH: // Do thread-specific cleanup.
            break;
        case DLL_PROCESS_DETACH: // Perform any necessary cleanup.
            break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}
#endif
