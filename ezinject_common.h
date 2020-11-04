#ifndef __EZINJECT_COMMON_H
#define __EZINJECT_COMMON_H

#define UPTR(x) ((uintptr_t)(x))
#define STRSZ(x) (strlen(x) + 1)

#define BR_STRTBL(br) ((char *)br + sizeof(*br) + (sizeof(char *) * br->argc))
#define STR_NEXT(entry) (entry) + *(unsigned int *)entry
#define STR_DATA(entry) ((char *)(entry)) + sizeof(unsigned int)

#define STRTBL_SKIP(stbl) stbl = STR_NEXT(stbl)

#define STRTBL_FETCH(stbl, out) do { \
	out = STR_DATA(stbl); \
	STRTBL_SKIP(stbl); \
} while(0)


#endif
