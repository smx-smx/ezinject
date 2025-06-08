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
	struct {
		void *(*fptr)(const char *filename, int flag);
		void *got;
		void *self;
	} dlopen;
	struct {
		void *(*fptr)(void *handle, const char *symbol);
		void *got;
		void *self;
	} dlsym;
	struct {
		int (*fptr)(void *handle);
		void *got;
		void *self;
	} dlclose;
	struct {
		char *(*fptr)(void);
		void *got;
		void *self;
	} dlerror;
};

struct thread_api {
	struct {
		int (*fptr)(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
		void *got;
		void *self;
	} pthread_mutex_init;
	struct {
		int (*fptr)(pthread_mutex_t *mutex);
		void *got;
		void *self;
	} pthread_mutex_lock;
	struct {
		int (*fptr)(pthread_mutex_t *mutex);
		void *got;
		void *self;
	} pthread_mutex_unlock;
	struct {
		int (*fptr)(pthread_cond_t *cond, const pthread_condattr_t *attr);
		void *got;
		void *self;
	} pthread_cond_init;
	struct {
		int (*fptr)(pthread_cond_t *restrict cond, pthread_mutex_t *restrict mutex);
		void *got;
		void *self;
	} pthread_cond_wait;
};

#endif
