/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>

#include "log.h"
#include "ezinject_util.h"
#include "ezinject_injcode.h"
#include "dlfcn_compat.h"

#define UNUSED(x) (void)(x)

LOG_SETUP(V_DBG);

int lib_preinit(struct injcode_user *user){
	UNUSED(user);
	// access user data
	return 0;
}

static char gPythonHome[255];
static char gPythonProgramName[] = "python";
static char gEnvPythonPath[2048] = "PYTHONPATH=";
static char *gEnvPythonIoEncoding = "PYTHONIOENCODING=UTF-8";

int lib_main(int argc, char *argv[]){
	lputs("Hello World from main");
	for(int i=0; i<argc; i++){
		lprintf("argv[%d] = %s\n", i, argv[i]);
	}

	if(argc < 5){
		lprintf(
			"Usage: %s [libpython.so] [PYTHONHOME] [PYTHONPATH] [script.py]\n"
			"  PYTHONHOME: root directory of the Python installation\n"
			"              example: /usr/lib/python2.7\n"
			"  PYTHONPATH: colon delimited list of paths to probe for Python imports\n"
			"              example: /usr/lib/python2.7:/usr/lib/python2.7/plat-x86_64-linux-gnu\n"
			, argv[0]);
		return 1;
	}

	const char *libPythonPath = argv[1];
	const char *pythonHome  = argv[2];
	const char *pythonPath = argv[3];
	const char *pythonScript  = argv[4];

	strncpy(gPythonHome, pythonHome, sizeof(gPythonHome));

	/**
	 * add the folder holding libpython to LD_LIBRARY_PATH
	 **/

	char *libPython_dir = strdup(libPythonPath);
	char *libdir = dirname(libPython_dir);

	char *env;
	char *current_libpath = getenv("LD_LIBRARY_PATH");
	if(current_libpath == NULL){
		asprintf(&env, "LD_LIBRARY_PATH=%s", libdir);
	} else if(strstr(current_libpath, libdir) == NULL) {
		asprintf(&env, "LD_LIBRARY_PATH=%s:%s", current_libpath, libdir);
	}
	free(libdir);

	putenv(env);
	free(env);

	/**
	 * Load libpython and resolve symbols
	 **/
	void *hpy = LIB_OPEN(libPythonPath);
	if(hpy == NULL){
		lprintf("dlopen '%s' failed: %s\n", libPythonPath, LIB_ERROR());
		return 1;
	}

	void (*Py_SetProgramName)(char *) = LIB_GETSYM(hpy, "Py_SetProgramName");
	void (*Py_SetPythonHome)(char *) = LIB_GETSYM(hpy, "Py_SetPythonHome");
	void (*Py_Initialize)(void) = LIB_GETSYM(hpy, "Py_Initialize");
	void (*PyEval_InitThreads)(void) = LIB_GETSYM(hpy, "PyEval_InitThreads");
	int (*PyRun_SimpleString)(char *) = LIB_GETSYM(hpy, "PyRun_SimpleString");
	void (*Py_Finalize)(void) = LIB_GETSYM(hpy, "Py_Finalize");
	int (*Py_IsInitialized)(void) = LIB_GETSYM(hpy, "Py_IsInitialized");

	if(Py_SetProgramName == NULL
	   || Py_SetPythonHome == NULL
	   || Py_Initialize == NULL
	   || PyEval_InitThreads == NULL
	   || PyRun_SimpleString == NULL
	   || Py_Finalize == NULL
	   || Py_IsInitialized == NULL
	){
		lprintf("Some python symbols could not be resolved\n");
		return 1;
	}

	/**
	 * Obtain script directory and filename
	 **/

	char *pyScript_dir = strdup(pythonScript);
	char *scriptDir = dirname(pyScript_dir);

	char *pyScript_filename = strdup(pythonScript);
	char *lastdot = strrchr(pyScript_filename, '.');
	*lastdot = '\0';

	char *scriptName = basename(pyScript_filename);

	lprintf("Script: %s\n", pythonScript);
	lprintf("Script dir: %s, filename: %s\n", scriptDir, scriptName);
	// prepend script directory
	strncat(gEnvPythonPath, scriptDir, sizeof(gEnvPythonPath)-1);
	{
		char *end = strchr(gEnvPythonPath, '\0');
		#ifdef EZ_TARGET_WINDOWS
		*(end++) = ';';
		#else
		*(end++) = ':';
		#endif
		*end = '\0';
	}
	strncat(gEnvPythonPath, pythonPath, sizeof(gEnvPythonPath)-1);

	putenv(gEnvPythonPath);
	putenv(gEnvPythonIoEncoding);


	/**
	 * Initialize the interpreter
	 **/

	int wasInitialized = Py_IsInitialized();
	if(!wasInitialized){
		lprintf("Initializing...\n");
		Py_SetPythonHome(gPythonHome);
		PyEval_InitThreads();

		Py_SetProgramName(gPythonProgramName);

		lprintf("Calling Py_Initialize...\n");
		Py_Initialize();
	}

	/**
	 * Run the python script
	 **/

	char *pyCode;
	asprintf(&pyCode, "import %s\n", scriptName);
	if(PyRun_SimpleString(pyCode) < 0){
		lprintf("An error or exception occured\n");
	}

	/**
	 * Cleanup
	 **/

	free(pyCode);
	free(pyScript_dir);
	free(pyScript_filename);

	if(!wasInitialized){
		lprintf("Finalizing...\n");
		Py_Finalize();
	}

	lprintf("Done\n");
	return 0;
}
