#include <pthread.h>

#include "ezinject.h"
#include "crt.h"
#include "log.h"

EZAPI crt_thread_create(struct injcode_bearing *br, crt_thread_func_t pfnThreadEntry){
	DBG("pthread_create");
	if(pthread_create(&br->user_tid, NULL, pfnThreadEntry, br) < 0){
		PERROR("pthread_create");
		return -1;
	}
	return 0;
}

EZAPI crt_thread_notify(struct injcode_bearing *br){
	DBG("sending pthread signal");
	pthread_mutex_lock(&br->mutex);
	{
		br->loaded_signal = 1;
		pthread_cond_signal(&br->cond);
	}
	pthread_mutex_unlock(&br->mutex);
	return 0;
}