#include <windows.h>
#include "ezinject.h"
#include "crt.h"

EZAPI crt_thread_create(struct injcode_bearing *br, crt_thread_func_t pfnThreadEntry){
	br->hThread = CreateThread(
		NULL,
		0,
		pfnThreadEntry,
		br,
		0,
		&br->user_tid
	);
	if(br->hThread == INVALID_HANDLE_VALUE){
		PERROR("CreateThread");
		return -1;
	}
	return 0;
}

EZAPI crt_thread_notify(struct injcode_bearing *br){
	if(SetEvent(br->hEvent) == FALSE){
		PERROR("SetEvent");
		return -1;
	}
	return 0;
}