/*
 * Copyright (C) 2025 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#ifndef __EZINJECT_CRT_INJCODE_H
#define __EZINJECT_CRT_INJCODE_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include "config.h"
#include "ezinject_compat.h"

#define CPLAPI SECTION("crtpayload")
extern uint8_t __start_crtpayload SECTION_START("crtpayload");
extern uint8_t __stop_crtpayload SECTION_END("crtpayload");

struct inj_unload_call {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool relocated;
    void *lib_handle;
    int (*dlclose)(void *handle);
    void (*pthread_exit)(void *retval);
    void *(*memcpy)(void *destination, const void *source, size_t num);
    int (*pthread_mutex_lock)(pthread_mutex_t *mutex);
	int (*pthread_mutex_unlock)(pthread_mutex_t *mutex);
    int (*pthread_cond_wait)(pthread_cond_t *restrict cond, pthread_mutex_t *restrict mutex);
    int (*pthread_join)(pthread_t thread, void **value_ptr);
    int (*pthread_cond_signal)(pthread_cond_t *cond);
    int (*mprotect)(void *addr, size_t size, int prot);
    pthread_t caller_tid;
    uint8_t *code;
    size_t code_size;
    off_t stage2_offset;
    size_t pagesize;
};

void CPLAPI crt_inj_unload(struct inj_unload_call *call);
void CPLAPI crt_inj_unload2(struct inj_unload_call *call, struct inj_unload_call *parent);

#endif