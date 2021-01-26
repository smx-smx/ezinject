#ifndef __EZINJECT_COMMON_H
#define __EZINJECT_COMMON_H

#define UNUSED(x) (void)(x)
#define ALIGNMSK(y) ((y)-1)

#ifdef ALIGN
#undef ALIGN
#endif

#define ALIGN(x, y) ((void *)((UPTR(x) + ALIGNMSK(y)) & ~ALIGNMSK(y)))

#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

#define WORDALIGN(x) ALIGN(x, sizeof(void *))

#define PAGEALIGN(x)  ALIGN(x, getpagesize())

#define UPTR(x) ((uintptr_t)(x))
#define PTRADD(a, b) ( UPTR(a) + UPTR(b) )
#define PTRDIFF(a, b) ( UPTR(a) - UPTR(b) )

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
