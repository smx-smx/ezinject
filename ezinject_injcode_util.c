/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */

INLINE void inj_dchar(struct injcode_bearing *br, char ch){
#ifdef DEBUG
	//pl:x\n\0
	volatile uint64_t str = str64(0x706C3A0000000000 | (((uint64_t)ch << 32) & 0xFF00000000));
	inj_puts(br, (char *)&str);
#endif
}

INLINE void *inj_memset(void *s, int c, size_t n){
	volatile unsigned char* p=s;
	while(n--){
		*p++ = (unsigned char)c;
	}
    return s;
}

#ifdef EZ_ARCH_ARM
INLINE void inj_cacheflush(struct injcode_bearing *br, void *from, void *to){
	br->libc_syscall(__ARM_NR_cacheflush, from, to, 0);
}
#else
INLINE void inj_cacheflush(struct injcode_bearing *br, void *from, void *to){
	UNUSED(br);
	UNUSED(from);
	UNUSED(to);
}
#endif

INLINE void inj_dbgptr(struct injcode_bearing *br, void *ptr){
#ifdef DEBUG
	char buf[(sizeof(uintptr_t) * 2) + 1];
	itoa16((uintptr_t)ptr, buf);
	inj_puts(br, buf);
#endif
}
