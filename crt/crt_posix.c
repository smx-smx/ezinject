/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <pthread.h>

#include "ezinject.h"
#include "crt.h"
#include "log.h"

EZAPI crt_thread_create(struct injcode_bearing *br, crt_thread_func_t pfnThreadEntry){
	DBG("pthread_create");
	pthread_t tid;
	if(pthread_create(&tid, NULL, pfnThreadEntry, br) < 0){
		PERROR("pthread_create");
		return -1;
	}
	pthread_detach(tid);
	br->user_tid = tid;
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
