#include "ezinject_injcode.h"

INLINE void *get_libdl(struct injcode_bearing *br){
	char *libdl_name = STR_DATA(BR_STRTBL(br));
	struct link_map *libdl = (struct link_map *) br->libc_dlopen(libdl_name, RTLD_NOW | __RTLD_DLOPEN);
	return (void *)libdl->l_addr;
}