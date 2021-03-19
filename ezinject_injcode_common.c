INLINE void itoa16(uintptr_t addr, char *buf){
        int i, j;
        int n = sizeof(addr) * 2;
        for(i=0, j=n-1; i<n; i++, j--){
                int digit = addr & 0xF;
                if(digit < 10) buf[j] = '0' + digit;
                else buf[j] = 'a' + (digit - 10);
                addr >>= 4;
        }
        buf[i++] = '\0';
}
