#include <windows.h>
#include "ezinject.h"
#include "crt.h"

EZAPI crt_thread_create(struct crt_ctx *ctx, crt_thread_func_t pfnThreadEntry){
	HANDLE hThread = CreateThread(
		NULL,
		0,
		pfnThreadEntry,
		ctx->local_br,
		0,
		&br->user_tid
	);
	ctx->shared_br->hThread = hThread;
	ctx->local_br->hThread = hThread;

	if(hThread == INVALID_HANDLE_VALUE){
		PERROR("CreateThread");
		return -1;
	}
	return 0;
}

EZAPI crt_thread_notify(struct injcode_bearing *br){
	if(SetEvent(ctx->shared_br->hEvent) == FALSE){
		PERROR("SetEvent");
		return -1;
	}
	return 0;
}