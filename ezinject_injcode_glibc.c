#include "ezinject_injcode.h"
#include <link.h>

INLINE void *inj_get_libdl(struct injcode_ctx *ctx){
	struct injcode_bearing *br = ctx->br;

	char *libdl_name = STR_DATA(BR_STRTBL(br));
	struct link_map *libdl = (struct link_map *) br->libc_dlopen(libdl_name, RTLD_NOW | __RTLD_DLOPEN);
	return (void *)libdl->l_addr;
}