#ifndef __EZINJECT_COMMON_H
#define __EZINJECT_COMMON_H

#define UNUSED(x) (void)(x)
#define ALIGNMSK(y) ((y)-1)

#ifdef ALIGN
#undef ALIGN
#endif

#define ALIGN(x, y) VPTR((UPTR(x) + ALIGNMSK(y)) & ~ALIGNMSK(y))
#define WORDALIGN(x) ALIGN(x, sizeof(void *))
#define PAGEALIGN(x)  ALIGN(x, getpagesize())

#define VPTR(x) ((void *)(x))
#define UPTR(x) ((uintptr_t)(x))
#define PTRADD(a, b) ( UPTR(a) + UPTR(b) )
#define PTRDIFF(a, b) ( UPTR(a) - UPTR(b) )

#define STRSZ(x) (strlen(x) + 1)

#define BR_STRTBL(br) ((char *)br + sizeof(*br) + (sizeof(char *) * br->argc))
#define STR_ENTSIZE(entry) *(unsigned int *)(entry)
#define STR_NEXT(entry) (entry) + STR_ENTSIZE(entry)
#define STR_DATA(entry) ((char *)(entry)) + sizeof(unsigned int)

#define STRTBL_SKIP(stbl) stbl = STR_NEXT(stbl)

#define STRTBL_FETCH(stbl, out) do { \
	out = STR_DATA(stbl); \
	STRTBL_SKIP(stbl); \
} while(0)

#endif
