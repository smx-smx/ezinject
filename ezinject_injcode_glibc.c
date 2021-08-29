#include "ezinject_injcode.h"
#include <link.h>

//#define SIMULATE_EGLIBC_BUG

INLINE void *inj_get_libdl(struct injcode_ctx *ctx){
	struct injcode_bearing *br = ctx->br;

	char *libdl_name = STR_DATA(BR_STRTBL(br));
	struct link_map *libdl = (struct link_map *) br->libc_dlopen(libdl_name, RTLD_NOW | __RTLD_DLOPEN);
	if(libdl == NULL){
		return NULL;
	}
#ifdef SIMULATE_EGLIBC_BUG
	return NULL;
#else
	return (void *)libdl->l_addr;
#endif
}