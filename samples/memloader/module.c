#include <stdio.h>
#include "ezinject_injcode.h"

int lib_preinit(struct injcode_user *user){
	UNUSED(user);
	return 0;
}

int lib_main(int argc, char *argv[]){
	puts("Hello World");
	return 0;
}