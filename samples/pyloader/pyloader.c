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

#include "ezinject_module.h"

/**
 * basename and dirname might modify the source path.
 * they also return a pointer to static memory that might be overwritten in subsequent calls
 */
char *my_basename(const char *path){
	char *cpy = strdup(path);
	if(!cpy) return NULL;
	char *ret = basename(cpy);
	ret = strdup(ret);
	free(cpy);
	return ret;
}
char *my_dirname(const char *path){
	char *cpy = strdup(path);
	if(!cpy) return NULL;
	char *ret = dirname(cpy);
	ret = strdup(ret);
	free(cpy);
	return ret;
}

static bool user_persist = false;

int lib_loginit(log_config_t *log_cfg){
	return -1;
}

int lib_preinit(struct injcode_user *user){
	user_persist = user->persist;
	// access user data
	return 0;
}

static void os_setenv(const char *key, const char *val){
	#ifdef EZ_TARGET_WINDOWS
	_putenv_s(key, val);
	#else
	setenv(key, val, 1);
	#endif
}

#ifdef EZ_TARGET_WINDOWS
#define PATH_DELIM ";"
#else
#define PATH_DELIM ":"
#endif

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

	const char *arg_libPythonPath = argv[1];
	const char *arg_pythonHome  = argv[2];
	const char *arg_pythonPath = argv[3];
	const char *arg_pythonScript  = argv[4];


	int rc = 1;

	char *pythonPath = NULL;
	char *scriptDir = NULL;
	char *scriptName = NULL;
	char *pyCode = NULL;

	do {
		/**
		* Load libpython and resolve symbols
		**/
		void *hpy = LIB_OPEN(arg_libPythonPath);
		if(hpy == NULL){
			lprintf("dlopen '%s' failed: %s\n", arg_libPythonPath, LIB_ERROR());
			break;
		}

		void (*Py_Initialize)(void) = LIB_GETSYM(hpy, "Py_Initialize");
		void (*PyEval_InitThreads)(void) = LIB_GETSYM(hpy, "PyEval_InitThreads");
		int (*PyRun_SimpleString)(const char *) = LIB_GETSYM(hpy, "PyRun_SimpleString");
		void (*Py_Finalize)(void) = LIB_GETSYM(hpy, "Py_Finalize");
		int (*Py_IsInitialized)(void) = LIB_GETSYM(hpy, "Py_IsInitialized");

		if(Py_Initialize == NULL
		|| PyEval_InitThreads == NULL
		|| PyRun_SimpleString == NULL
		|| Py_Finalize == NULL
		|| Py_IsInitialized == NULL
		){
			lprintf("Some python symbols could not be resolved\n");
			break;
		}

		lprintf("Script: %s\n", arg_pythonScript);

		/**
		* Obtain script directory and filename
		**/
		scriptDir = my_dirname(arg_pythonScript);


		// prepend script directory
		asprintf(&pythonPath, "%s"PATH_DELIM"%s", scriptDir, arg_pythonPath);
		if(!pythonPath){
			lprintf("asprintf() failed\n");
			break;
		}

		os_setenv("PYTHONHOME", arg_pythonHome);
		os_setenv("PYTHONPATH", pythonPath);
		os_setenv("PYTHONIOENCODING", "UTF-8");

		/**
		* Initialize the interpreter
		**/

		int wasInitialized = Py_IsInitialized();
		if(!wasInitialized){
			lprintf("Initializing...\n");
			PyEval_InitThreads();

			lprintf("Calling Py_Initialize...\n");
			Py_Initialize();
		}

		/**
		* Run the python script
		**/

		scriptName = my_basename(arg_pythonScript);
		if(!scriptName){
			break;
		}
		char *lastdot = strrchr(scriptName, '.');
		if(lastdot){
			*lastdot = '\0';
		}

		lprintf("Script dir: %s, filename: %s\n", scriptDir, scriptName);

		asprintf(&pyCode, "import %s\n", scriptName);
		if(PyRun_SimpleString(pyCode) < 0){
			lprintf("An error or exception occured\n");
		}

		/**
		* Cleanup
		**/

		if(!user_persist && !wasInitialized){
			lprintf("Finalizing...\n");
			Py_Finalize();
		}

		lprintf("Done\n");
		rc = 0;
	} while(0);

	if(pyCode) free(pyCode);
	if(pythonPath) free(pythonPath);
	if(scriptDir) free(scriptDir);
	if(scriptName) free(scriptName);

	return rc;
}
