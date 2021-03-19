INLINE void inj_dchar(struct injcode_bearing *br, char ch){
	//pl:x\n\0
	volatile uint64_t str = str64(0x706C3A0000000000 | (((uint64_t)ch << 32) & 0xFF00000000));
	inj_puts(br, (char *)&str);
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