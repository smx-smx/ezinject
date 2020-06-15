#include "ezinject_injcode.h"
#include "log.h"

extern int lib_preinit(struct injcode_user *user);
extern int lib_main(int argc, char *argv[]);

int crt_userinit(struct injcode_bearing *br){
	int result;
	result = lib_preinit(&br->user);
	if(result != 0){
		ERR("lib_preinit returned nonzero status %d, aborting...", result);
	} else {
		result = lib_main(br->argc, br->argv);
	}

	DBG("lib_main returned: %d", result);

	return result;
}