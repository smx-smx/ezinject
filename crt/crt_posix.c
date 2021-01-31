#include <pthread.h>

#include "ezinject.h"
#include "crt.h"
#include "log.h"

EZAPI crt_thread_create(struct crt_ctx *ctx, crt_thread_func_t pfnThreadEntry){
	DBG("pthread_create");
	pthread_t tid;
	if(pthread_create(&tid, NULL, pfnThreadEntry, ctx->local_br) < 0){
		PERROR("pthread_create");
		return -1;
	}
	ctx->shared_br->user_tid = tid;
	ctx->local_br->user_tid = tid;
	return 0;
}

EZAPI crt_thread_notify(struct crt_ctx *ctx){
	struct injcode_bearing *br = ctx->shared_br;

	DBG("sending pthread signal");
	pthread_mutex_lock(&br->mutex);
	{
		br->loaded_signal = 1;
		pthread_cond_signal(&br->cond);
	}
	pthread_mutex_unlock(&br->mutex);
	return 0;
}