/**
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 **/
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "config.h"
#include "log.h"

#include "ezinject_common.h"
#include "ezinject_injcode.h"

#include <sapi/embed/php_embed.h>

LOG_SETUP(V_DBG);

int lib_preinit(struct injcode_user *user){
	user->persist = 1;
	UNUSED(user);
	return 0;
}

struct thread_arg {
	int argc;
	char **argv;
};

#ifdef USE_FRIDA_GUM
#define FRIDA_API(x) \
	extern void x(); \
	void __attribute__ ((visibility ("hidden"))) \
		(*__imported_ ## x) = &x

FRIDA_API(glib_init);
FRIDA_API(gum_init);
FRIDA_API(gum_interceptor_begin_transaction);
FRIDA_API(gum_make_call_listener);
FRIDA_API(gum_interceptor_attach);
FRIDA_API(gum_interceptor_replace);
#endif

void *run_php(void *arg){
	struct thread_arg *param = (struct thread_arg *)arg;
	int rc = -1;

	putenv("PHP_INI_SCAN_DIR=/tmp");

	PHP_EMBED_START_BLOCK(param->argc, param->argv)
	do {
		INFO("Running %s", param->argv[0]);
		zend_file_handle file_handle;
		zend_stream_init_filename(&file_handle, param->argv[0]);

		if(php_execute_script(&file_handle) == FAILURE){
			break;
		}
		rc = 0;
	} while(0);
	PHP_EMBED_END_BLOCK()

	for(int i=0; i<param->argc; i++){
		free(param->argv[i]);
	}
	free(param->argv);
	free(param);

	return (void *)rc;
}

int lib_main(int argc, char *argv[]){
	lputs("Hello World from main");
	for(int i=0; i<argc; i++){
		lprintf("argv[%d] = %s\n", i, argv[i]);
	}

	int rc = -1;
	char *scriptFile = argv[1];

	struct thread_arg *arg = calloc(1, sizeof(*arg));
	arg->argc = argc - 1;
	arg->argv = calloc(arg->argc, sizeof(char *));
	for(int i=0; i<arg->argc; i++){
		arg->argv[i] = strdup(argv[1+i]);
	}

	pthread_t tid;
	pthread_create(&tid, NULL, run_php, arg);
	return rc;
}