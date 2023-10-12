/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */

#ifndef __EZINJECT_INJCODE_POSIX_H
#define __EZINJECT_INJCODE_POSIX_H

#include <pthread.h>

struct dl_api {
	void *(*dlopen)(const char *filename, int flag);
	void *(*dlsym)(void *handle, const char *symbol);
	int (*dlclose)(void *handle);
	char *(*dlerror)(void);
};

struct thread_api {
	int (*pthread_mutex_init)(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
	int (*pthread_mutex_lock)(pthread_mutex_t *mutex);
	int (*pthread_mutex_unlock)(pthread_mutex_t *mutex);
	int (*pthread_cond_init)(pthread_cond_t *cond, const pthread_condattr_t *attr);
	int (*pthread_cond_wait)(pthread_cond_t *restrict cond, pthread_mutex_t *restrict mutex);
	int (*pthread_join)(pthread_t thread, void **retval);
};

#endif
