INLINE void inj_puts(struct injcode_bearing *br, char *str){
	if(str == NULL){
		return;
	}

	int l;
	for(l=0; str[l] != 0x00; l++);
	br->libc_syscall(__NR_write, STDOUT_FILENO, str, l);
	char nl = '\n';
	
	br->libc_syscall(__NR_write, STDOUT_FILENO, &nl, 1);
}