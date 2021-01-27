INLINE void inj_puts(struct injcode_bearing *br, char *str){
	if(str == NULL){
		return;
	}

	PPEB peb = br->RtlGetCurrentPeb();
	PINT_RTL_USER_PROCESS_PARAMETERS params = (PINT_RTL_USER_PROCESS_PARAMETERS)peb->ProcessParameters;
	
	HANDLE h = params->StandardOutput;
	if(h == INVALID_HANDLE_VALUE){
		return;
	}

	int l = 0;
	char *p = str;
	while(*(p++)) ++l;

	IO_STATUS_BLOCK stb;
	br->NtWriteFile(h, NULL, NULL, NULL, &stb, str, l, 0, NULL);

	char nl[2];
	nl[0] = '\r'; nl[1] = '\n';
	br->NtWriteFile(h, NULL, NULL, NULL, &stb, nl, sizeof(nl), 0, NULL);
}