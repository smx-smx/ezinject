#include <stdio.h>
#include <stdio.h>
#include "ezinject_injcode.h"


void lib_preinit(struct injcode_bearing *br){
	// access data in br
}

int lib_main(int argc, char *argv[]){
	puts("Hello World from main");
	for(int i=0; i<argc; i++){
		printf("argv[%d] = %s\n", i, argv[i]);
	}
	return 0;
}