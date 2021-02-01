/**
 * Copyright (C) 2020 Stefano Moioli <smxdev4@gmail.com>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <libgen.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <mono/jit/jit.h>
#include <mono/metadata/mono-config.h>
#include <mono/metadata/assembly.h>
#include <mono/metadata/debug-helpers.h>
#include <mono/metadata/threads.h>
#include <mono/metadata/mono-gc.h>
#include <mono/utils/mono-error.h>

#include "log.h"
#include "ezinject_compat.h"
#include "ezinject_injcode.h"
#include "util.h"

#include "interface/if_hook.h"


LOG_SETUP(V_DBG);

#define DEBUG

#ifdef _WIN32
#include <Windows.h>
#endif

#ifdef _WIN32
#define DLLEXPORT __declspec(dllexport) extern
#else
#define DLLEXPORT extern
#endif

#ifdef DEBUG
#define DPRINTF(fmt, ...) \
	lprintf("[%s]: " fmt, __func__, ##__VA_ARGS__)
#else
#define DPRINTF(fmt, ...)
#endif

#ifdef __i386__
  #if !defined(_WIN32) && !defined(__cdecl)
  #define __cdecl __attribute__((__cdecl__))
  #endif
#else
  #define __cdecl
#endif

static char *get_thismod_path(){
	FILE *maps = fopen("/proc/self/maps", "r");
	if(maps == NULL){
		return NULL;
	}

	char *result = NULL;

	// we're on temp stack, so we prefer heap
	char *path = malloc(256);
	char *line = malloc(256);
	do {
		while(fgets(line, 256, maps)){
			if(sscanf(line, "%*p-%*p %*s %*p %*x:%*x %*u %s", path) <= 0){
				continue;
			}
			if(strstr(path, MODULE_NAME".so")){
				result = path;
				break;
			}
		}
	} while(0);

	if(result == NULL){
		free(path);
	}
	free(line);

	fclose(maps);
	return result;
}

static MonoDomain * (*fn_mono_jit_init_version)      (const char *root_domain_name, const char *runtime_version);
static MonoDomain * (*fn_mono_domain_create_appdomain) (char *friendly_name, char *configuration_file);
static void (*fn_mono_domain_set_config) (MonoDomain *domain, const char *base_dir, const char *config_file_name);
static mono_bool (*fn_mono_domain_set)(MonoDomain *domain, mono_bool force);
static void (*fn_mono_set_dirs) (const char *assembly_dir, const char *config_dir);
static void (*fn_mono_domain_unload) (MonoDomain *domain);
static MonoAssembly * (*fn_mono_domain_assembly_open)  (MonoDomain *domain, const char *name);
static void (*fn_mono_config_parse)        (const char *filename);
static void (*fn_mono_assembly_load_reference) (MonoImage *image, int index);
static void (*fn_mono_assembly_foreach)    (MonoFunc func, void* user_data);
static MonoImage* (*fn_mono_assembly_get_image)  (MonoAssembly *assembly);
static MonoThread* (*fn_mono_thread_attach) (MonoDomain *domain);
static void (*fn_mono_thread_detach) (MonoThread *thread);
static MonoObject* (*fn_mono_runtime_invoke)         (MonoMethod *method, void *obj, void **params, MonoObject **exc);
static void (*fn_mono_print_unhandled_exception) (MonoObject *exc);
static MonoMethodDesc* (*fn_mono_method_desc_new) (const char *name, mono_bool include_namespace);
static void            (*fn_mono_method_desc_free) (MonoMethodDesc *desc);
static MonoMethod*     (*fn_mono_method_desc_search_in_image) (MonoMethodDesc *desc, MonoImage *image);
static int (*fn_mono_image_get_table_rows) (MonoImage *image, int table_id);
static const char*       (*fn_mono_assembly_name_get_name) (MonoAssemblyName *aname);
static MonoAssemblyName *(*fn_mono_assembly_get_name) (MonoAssembly *assembly);
static MonoDomain* (*fn_mono_get_root_domain)(void);

typedef struct {
	void *(*malloc)      (size_t n_bytes);
	void *(*realloc)     (void *mem, size_t n_bytes);
	void  (*free)        (void *mem);
	void *(*calloc)      (size_t n_blocks, size_t n_block_bytes);
} GMemVTable;
static void (*fn_monoeg_g_mem_set_vtable)(GMemVTable *vtable);

int loadLibMono(const char *libPath){
	// RTLD_DEEPBIND is required to trump over LD_PRELOAD
	void *libstdcpp = dlopen_ex("libstdc++.so.6", RTLD_NOW | RTLD_GLOBAL | RTLD_DEEPBIND);
	if(libstdcpp == NULL){
		lprintf("dlopen '%s' failed (%s)\n", "libstdc++.so.6", dlerror());
		return -1;
	}

	// RTLD_DEEPBIND is required to trump over LD_PRELOAD
	void *hlib = dlopen_ex(libPath, RTLD_NOW | RTLD_GLOBAL | RTLD_DEEPBIND);
	if(hlib == NULL){
		lprintf("dlopen '%s' failed (%s)\n", libPath, dlerror());
		return -1;
	}
	lprintf("handle (%s): %p\n", libPath, *(void **)hlib);

	fn_mono_jit_init_version = dlsym(hlib, "mono_jit_init_version");
	fn_mono_domain_create_appdomain = dlsym(hlib, "mono_domain_create_appdomain");
	fn_mono_domain_set_config = dlsym(hlib, "mono_domain_set_config");
	fn_mono_get_root_domain = dlsym(hlib, "mono_get_root_domain");
	fn_mono_set_dirs = dlsym(hlib, "mono_set_dirs");
	fn_mono_domain_set = dlsym(hlib, "mono_domain_set");
	fn_mono_domain_unload = dlsym(hlib, "mono_domain_unload");
	fn_mono_domain_assembly_open = dlsym(hlib, "mono_domain_assembly_open");
	fn_mono_config_parse = dlsym(hlib, "mono_config_parse");
	fn_mono_assembly_load_reference = dlsym(hlib, "mono_assembly_load_reference");
	fn_mono_assembly_foreach = dlsym(hlib, "mono_assembly_foreach");
	fn_mono_assembly_get_image = dlsym(hlib, "mono_assembly_get_image");
	fn_mono_thread_attach = dlsym(hlib, "mono_thread_attach");
	fn_mono_thread_detach = dlsym(hlib, "mono_thread_detach");
	fn_mono_runtime_invoke = dlsym(hlib, "mono_runtime_invoke");
	fn_mono_print_unhandled_exception = dlsym(hlib, "mono_print_unhandled_exception");
	fn_mono_method_desc_new = dlsym(hlib, "mono_method_desc_new");
	fn_mono_method_desc_free = dlsym(hlib, "mono_method_desc_free");
	fn_mono_method_desc_search_in_image = dlsym(hlib, "mono_method_desc_search_in_image");
	fn_mono_image_get_table_rows = dlsym(hlib, "mono_image_get_table_rows");
	fn_mono_assembly_name_get_name = dlsym(hlib, "mono_assembly_name_get_name");
	fn_mono_assembly_get_name = dlsym(hlib, "mono_assembly_get_name");
	fn_monoeg_g_mem_set_vtable = dlsym(hlib, "monoeg_g_mem_set_vtable");

	return !(
		fn_mono_jit_init_version
		&& fn_mono_domain_create_appdomain
		&& fn_mono_domain_set_config
		&& fn_mono_get_root_domain
		&& fn_mono_domain_set
		&& fn_mono_domain_unload
		&& fn_mono_domain_assembly_open
		&& fn_mono_config_parse
		&& fn_mono_assembly_load_reference
		&& fn_mono_assembly_foreach
		&& fn_mono_assembly_get_image
		&& fn_mono_thread_attach
		&& fn_mono_thread_detach
		&& fn_mono_runtime_invoke
		&& fn_mono_print_unhandled_exception
		&& fn_mono_method_desc_new
		&& fn_mono_method_desc_free
		&& fn_mono_method_desc_search_in_image
		&& fn_mono_image_get_table_rows
		&& fn_mono_assembly_name_get_name
		&& fn_mono_assembly_get_name
		&& fn_mono_set_dirs
		&& fn_monoeg_g_mem_set_vtable
	);
}

static MonoMethod *imageFindMethod(MonoImage *image, const char *methodName) {
	MonoMethodDesc *desc = fn_mono_method_desc_new(methodName, false);
	if (desc == NULL) {
		lprintf("Invalid method name '%s'\n", methodName);
		return NULL;
	}
	MonoMethod *method = fn_mono_method_desc_search_in_image(desc, image);
	fn_mono_method_desc_free(desc);
	if (method == NULL) {
		return NULL;
	}
	return method;
}

static void findAndRun(void *refAsmPtr, void *userdata){
	void **pPointers = (void **)userdata;
	const char *monoMethodName = (const char *)pPointers[0];
	const char *m_asmName = (const char *)pPointers[1];
	bool *pMethodInvoked = (bool *)pPointers[2];

	if(*pMethodInvoked)
		return;

	MonoAssembly *refAsm = (MonoAssembly *)refAsmPtr;
	const char *asmName = fn_mono_assembly_name_get_name(fn_mono_assembly_get_name(refAsm));
	if(strcmp(asmName, m_asmName) != 0)
		return;

	MonoImage *refAsmImage = fn_mono_assembly_get_image(refAsm);
	if (refAsmImage == NULL) {
		lprintf("Cannot get image for assembly '%s'\n", asmName);
		return;
	}

	MonoMethod *method = imageFindMethod(refAsmImage, monoMethodName);
	if(method == NULL)
		return;

	MonoObject *exception = NULL;
	void **args = NULL;
	fn_mono_runtime_invoke(method, NULL, args, &exception);

	*pMethodInvoked = true;

	if (exception) {
		fn_mono_print_unhandled_exception(exception);
	}
}

static int runMethod(MonoDomain *appDomain, MonoAssembly *assembly, const char *methodDesc){
	const char *asmName = fn_mono_assembly_name_get_name(fn_mono_assembly_get_name(assembly));
	MonoThread *thread = fn_mono_thread_attach(appDomain);

	bool methodInvoked = false;

	void *pUserData[] = {
		(void *)methodDesc,
		(void *)asmName,
		(void *)&methodInvoked
	};
	fn_mono_assembly_foreach(findAndRun, pUserData);

	fn_mono_thread_detach(thread);
	return 0;
}

typedef size_t PLGHANDLE;

#define NULL_PLGHANDLE 0

#ifdef _WIN32
//https://stackoverflow.com/a/20387632
bool launchDebugger() {
	std::wstring systemDir(MAX_PATH + 1, '\0');
	UINT nChars = GetSystemDirectoryW(&systemDir[0], systemDir.length());
	if (nChars == 0)
		return false;
	systemDir.resize(nChars);

	DWORD pid = GetCurrentProcessId();
	std::wostringstream s;
	s << systemDir << L"\\vsjitdebugger.exe -p " << pid;
	std::wstring cmdLine = s.str();

	STARTUPINFOW si;
	memset(&si, 0x00, sizeof(si));
	si.cb = sizeof(si);

	PROCESS_INFORMATION pi;
	memset(&pi, 0x00, sizeof(pi));

	if (!CreateProcessW(
		NULL, &cmdLine[0],
		NULL, NULL,
		false, 0, NULL, NULL,
		&si, &pi
	)) {
		return false;
	}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	while (!IsDebuggerPresent())
		Sleep(100);

	DebugBreak();
	return true;
}

#endif

//#define LAUNCH_DEBUGGER


/*
	* Initializes the Mono runtime
	*/
int __cdecl clrInit(
	const char *assemblyPath, const char *pluginFolder,
	MonoDomain **monoDomainOut,
	MonoAssembly **monoAssemblyOut
) {
#if defined(_WIN32) && defined(DEBUG)

#ifdef LAUNCH_DEBUGGER
	launchDebugger();
#endif

	AllocConsole();
	freopen("CONIN$", "r", stdin);
	freopen("CONOUT$", "w", stdout);
	freopen("CONOUT$", "w", stderr);

#if 0
	setvbuf(stdout, NULL, 0, _IONBF);
	setvbuf(stderr, NULL, 0, _IONBF);
#endif
#endif

	DPRINTF("\n");

	/**
	 * Get Paths
	 */
	char *asmPrefix = strdup(assemblyPath);
	remove_ext(asmPrefix);

	char *asmFilename = basename_ex(assemblyPath);
	remove_ext(asmFilename);

	MonoThread *rootThread = NULL;
	MonoDomain *rootDomain = fn_mono_get_root_domain();

	int rc = -1;
	do {
		DPRINTF("loading %s\n", assemblyPath);

		if(rootDomain == NULL){
			DPRINTF("initializing mono\n");

			rootDomain = fn_mono_jit_init_version("SharpInj", "v4.0");
			if (!rootDomain) {
				lprintf("Failed to initialize mono\n");
				return -1;
			}

			// Load the default mono configuration file
			fn_mono_config_parse(NULL);

			DPRINTF("mono initialization completed\n");
		} else {
			DPRINTF("attaching...\n");
			rootThread = fn_mono_thread_attach(rootDomain);
		}

		/**
		 * Create AppDomain
		 */
		DPRINTF("creating appdomain...\n");
		MonoDomain *newDomain = fn_mono_domain_create_appdomain(asmFilename, NULL);

		char *configPath = asprintf_ex("%s.config", asmPrefix);
		fn_mono_domain_set_config(newDomain, pluginFolder, configPath);
		free(configPath);

		*monoDomainOut = newDomain;

		DPRINTF("loading assembly...\n");
		MonoAssembly *pluginAsm = fn_mono_domain_assembly_open(newDomain, assemblyPath);
		if (!pluginAsm) {
			lprintf("Failed to open assembly '%s'\n", assemblyPath);
			break;
		}

		*monoAssemblyOut = pluginAsm;

		MonoImage *image = fn_mono_assembly_get_image(pluginAsm);
		if (!image) {
			lprintf("Failed to get image\n");
			break;
		}

		// NOTE: can't use fn_mono_assembly_load_references (it's deprecated and does nothing)
		int numAssemblies = fn_mono_image_get_table_rows(image, MONO_TABLE_ASSEMBLYREF);
		for (int i = 0; i < numAssemblies; i++) {
			fn_mono_assembly_load_reference(image, i);
		}

		rc = 0;
	} while(0);

	free(asmPrefix);
	free(asmFilename);

	if(rootThread != NULL){
		fn_mono_thread_detach(rootThread);
	}
	return rc;
}

int lib_preinit(struct injcode_user *user){
	UNUSED(user);
	return 0;
}

static void adjust_ldpath(const char *libMonoPath){
	char *libdir = dirname_ex(libMonoPath);
	char *current_libpath = getenv("LD_LIBRARY_PATH");

	char *thisModPath = get_thismod_path();
	char *thisModDir = dirname_ex(thisModPath);

	lprintf("LD_LIBRARY_PATH is '%s'\n", current_libpath);

	char *env = NULL;
	if(current_libpath == NULL){
		env = asprintf_ex("LD_LIBRARY_PATH=%s:%s", thisModDir, libdir);
	} else if(strstr(current_libpath, libdir) == NULL) {
		env = asprintf_ex("LD_LIBRARY_PATH=%s:%s:%s", thisModDir, libdir, current_libpath);
	}

	if(env != NULL){
		lprintf("Setting %s\n", env);
		putenv(env);
		free(env);
	}

	free(thisModDir);
	free(thisModPath);

	free(libdir);
}

int lib_main(int argc, char *argv[]){
	if(argc < 6){
		lprintf("Usage: %s [libMono.so] [libsDir] [configDir] [assembly] [method]\n", argv[0]);
		return 1;
	}

	char *libMonoPath = argv[1];
	char *monoLibsDir = argv[2];
	char *monoConfigDir = argv[3];

	char *asmToLoad = argv[4];
	char *methodDesc = argv[5];

	adjust_ldpath(libMonoPath);

	lprintf("Loading libMono...\n");
	if(loadLibMono(libMonoPath) != 0){
		lprintf("loadLibMono() failed\n");
		return 1;
	}

	lprintf("Begin...\n");
	//putenv("MONO_THREADS_SUSPEND=preemptive");

	void *hlibc = dlopen("libc.so.6", RTLD_NOW | RTLD_NOLOAD);
	if(!hlibc){
		lprintf("libc.so.6 not loaded\n");
		return 1;
	}

	/**
	 * For systems that override malloc/free (e.g via LD_PRELOAD), get the real ones
	 * required since mono expects malloc to perform aligned allocations for vtable
	 */
	void *pfnMalloc = dlsym(hlibc, "malloc");
	void *pfnFree = dlsym(hlibc, "free");
	void *pfnRealloc = dlsym(hlibc, "realloc");
	void *pfnCalloc = dlsym(hlibc, "calloc");

	GMemVTable vt = {
		.malloc = pfnMalloc,
		.free = pfnFree,
		.realloc = pfnRealloc,
		.calloc = pfnCalloc
	};
	fn_monoeg_g_mem_set_vtable(&vt);

	dlclose(hlibc);

	fn_mono_set_dirs(monoLibsDir, monoConfigDir);

	char *assemblyDir = dirname_ex(asmToLoad);

	MonoDomain *appDomain;
	MonoAssembly *monoAsm;
	if(clrInit(asmToLoad, assemblyDir, &appDomain, &monoAsm) != 0){
		lprintf("clrInit failed\n");
	} else {
		runMethod(appDomain, monoAsm, methodDesc);

		MonoThread *thread = fn_mono_thread_attach(appDomain);
		fn_mono_domain_unload(appDomain);
		fn_mono_thread_detach(thread);
	}

	free(assemblyDir);

	return 0;
}


