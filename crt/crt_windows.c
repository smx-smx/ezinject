#include <windows.h>
#include "ezinject.h"
#include "crt.h"
#include "log.h"

EZAPI crt_thread_create(struct crt_ctx *ctx, crt_thread_func_t pfnThreadEntry){
	DWORD dwThreadId;
	HANDLE hThread = CreateThread(
		NULL,
		0,
		pfnThreadEntry,
		ctx->local_br,
		0,
		&dwThreadId
	);
	ctx->shared_br->hThread = hThread;
	ctx->shared_br->user_tid = dwThreadId;
	ctx->local_br->hThread = hThread;
	ctx->local_br->user_tid = dwThreadId;

	if(hThread == INVALID_HANDLE_VALUE){
		PERROR("CreateThread");
		return -1;
	}
	return 0;
}

EZAPI crt_thread_notify(struct crt_ctx *ctx){
	if(SetEvent(ctx->shared_br->hEvent) == FALSE){
		PERROR("SetEvent");
		return -1;
	}
	return 0;
}