/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include "ezinject_injcode.h"
#include "log.h"
#include "ezinject_module.h"
#include "crt_injcode.h"
#include "ezinject.h"

#include <sys/mman.h>

#include <signal.h>
#include <pthread.h>

ez_region region_crtpl_code = {
	.start = (void *)&__start_crtpayload,
	.end = (void *)&__stop_crtpayload
};

extern void *crt_userlib_handle;

struct inj_unload_call unload_call;


int lib_unload_prepare(){
	memset(&unload_call, 0x00, sizeof(unload_call));

	uint8_t code[REGION_LENGTH(region_crtpl_code)];
	size_t code_size = REGION_LENGTH(region_crtpl_code);
    memcpy(code, region_crtpl_code.start, sizeof(code));

	void *codePageStart = PAGEALIGN_DOWN(&code);
	void *codePageEnd = PAGEALIGN(PTRADD(codePageStart, sizeof(code)));

	if(mprotect(codePageStart,
		PTRDIFF(codePageEnd, codePageStart),
		PROT_READ | PROT_WRITE | PROT_EXEC
	) < 0){
        PERROR("mprotect");
		return -1;
    }

	struct inj_unload_call *call = &unload_call;

	call->lib_handle = crt_userlib_handle;
	call->dlclose = &dlclose;
	call->pthread_exit = &pthread_exit;
	call->pthread_mutex_lock = &pthread_mutex_lock;
	call->pthread_mutex_unlock = &pthread_mutex_unlock;
	call->pthread_cond_wait = &pthread_cond_wait;
	call->pthread_join = &pthread_join;
	call->mprotect = &mprotect;
	call->memcpy = &memcpy;
	call->code = code;
	call->code_size = code_size;
	call->caller_tid = pthread_self();
	call->pagesize = getpagesize();
	call->pthread_cond_signal = &pthread_cond_signal;
	pthread_mutex_init(&call->mutex, NULL);
	pthread_cond_init(&call->cond, NULL);

	off_t stage2_offset = PTRDIFF(&crt_inj_unload2, region_crtpl_code.start);
	call->stage2_offset = stage2_offset;

    void *pfnUnload = (void *)PTRADD(
        code,
        PTRDIFF(&crt_inj_unload, region_crtpl_code.start)
    );
	pthread_t tid;
	pthread_create(&tid, NULL, (void*(*)(void *))pfnUnload, call);
	pthread_detach(tid);

	pthread_mutex_lock(&call->mutex);
	while(!call->relocated){
		pthread_cond_wait(&call->cond, &call->mutex);
	}
	pthread_mutex_unlock(&call->mutex);
    return 0;
}

int crt_userinit(struct injcode_bearing *br){
	int result;
	result = lib_preinit(&br->user);
	if(result != 0){
		ERR("lib_preinit returned nonzero status %d, aborting...", result);
		return result;
	}

	log_set_leave_open(br->user.persist);
	result = lib_main(br->argc, br->argv);
	DBG("lib_main returned: %d", result);

	return result;
}
