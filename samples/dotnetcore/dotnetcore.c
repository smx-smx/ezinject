#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <libgen.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <unistd.h>

#include "log.h"
#include "util.h"
#include "interface/if_hook.h"
#include "interface/cpu/if_sljit.h"
#include "ezinject_injcode.h"

#include "coreclr_delegates.h"
#include "hostfxr.h"

LOG_SETUP(V_DBG);

int lib_preinit(struct injcode_user *user){
	UNUSED(user);
	return 0;
}

int lib_main(int argc, char *argv[]){
	if(argc < 2){
		lprintf("Usage: %s [assembly.dll][My.Class:Method]\n", argv[0]);
		return 1;
	}

	char *asmPath = argv[1];
	char *targetMethodDesc = argv[2];

	char *targetClassName = NULL;
	char *targetMethodName = NULL;

	char *methodDescComponents = strdup(targetMethodDesc);
	{
		char *sep = strrchr(methodDescComponents, ':');
		*sep = '\0';

		targetClassName = methodDescComponents;
		targetMethodName = sep + 1;
	}

	char *pathWithoutExtension = strdup(asmPath);
	remove_ext(pathWithoutExtension);

	char *asmDir = dirname_ex(asmPath);

	char *hostFxrPath = asprintf_ex("%s/libhostfxr.so", asmDir);
	char *runtimeConfigPath = asprintf_ex("%s.runtimeconfig.json", pathWithoutExtension);

	hostfxr_initialize_for_runtime_config_fn pfnInitializer = NULL;
	hostfxr_get_runtime_delegate_fn pfnGetDelegate = NULL;
	hostfxr_close_fn pfnClose = NULL;
	load_assembly_and_get_function_pointer_fn pfnLoadAssembly = NULL;

	hostfxr_handle runtimeHandle;

	component_entry_point_fn pfnEntry = NULL;

	int rc = 1;
	do {
		if(access(hostFxrPath, F_OK) < 0){
			lprintf("'%s' does not exist\n", hostFxrPath);
			break;
		}

		if(access(runtimeConfigPath, F_OK) < 0){
			lprintf("'%s' does not exist\n", runtimeConfigPath);
			break;
		}

		lprintf("=> Loading '%s'\n", hostFxrPath);

		void *hostfxr = dlopen(hostFxrPath, RTLD_NOLOAD);
		if(!hostfxr){
			hostfxr = dlopen(hostFxrPath, RTLD_NOW | RTLD_GLOBAL);
			if(!hostfxr){
				lprintf("dlopen '%s' failed: %s\n", hostFxrPath, dlerror());
				break;
			}
		}

		pfnInitializer = dlsym(hostfxr, "hostfxr_initialize_for_runtime_config");
		pfnGetDelegate = dlsym(hostfxr, "hostfxr_get_runtime_delegate");
		pfnClose = dlsym(hostfxr, "hostfxr_close");

		if(pfnInitializer == NULL || pfnGetDelegate == NULL || pfnClose == NULL){
			lprintf("failed to resolve libhostfxr symbols\n");
			break;
		}

		struct hostfxr_initialize_parameters initParams = {
			.size = sizeof(struct hostfxr_initialize_parameters),
			.host_path = asmDir,
			.dotnet_root = asmDir
		};

		pfnInitializer(runtimeConfigPath, &initParams, &runtimeHandle);
		if(runtimeHandle == NULL){
			lprintf("Failed to initialize dotnet core\n");
			break;
		}

		pfnGetDelegate(runtimeHandle, hdt_load_assembly_and_get_function_pointer, (void **)&pfnLoadAssembly);
		if(pfnLoadAssembly == NULL){
			lprintf("Failed to acquire load_assembly_and_get_function_pointer_fn\n");
			break;
		}

		lprintf("Loading '%s', then running %s in %s\n", asmPath, targetMethodName, targetClassName);
		pfnLoadAssembly(
			asmPath,
			targetClassName,
			targetMethodName,
			NULL, //-> public delegate int ComponentEntryPoint(IntPtr args, int sizeBytes);
			NULL,
			(void **)&pfnEntry);

		if(pfnEntry == NULL){
			lprintf("Failed to locate '%s:%s'\n", targetClassName, targetMethodName);
			break;
		}
		pfnEntry(NULL, 0);

		rc = 0;
	} while(0);

	free(methodDescComponents);
	free(pathWithoutExtension);
	free(asmDir);
	free(runtimeConfigPath);
	free(hostFxrPath);

	return rc;
}