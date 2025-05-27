#include <stdio.h>
#include "ezinject_module.h"

int lib_loginit(log_config_t *log_cfg){
	return -1;
}

int lib_preinit(struct injcode_user *user){
	UNUSED(user);
	return 0;
}

int lib_main(int argc, char *argv[]){
	puts("Hello World");
	return 0;
}
