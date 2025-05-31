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

	size_t pagesize = 0;
	#ifdef EZ_TARGET_WINDOWS
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	pagesize = sysInfo.dwPageSize;
	#else
	pagesize = getpagesize();
	#endif

	void *codePageStart = ALIGN_DOWN(&code, pagesize);
	void *codePageEnd = ALIGN(PTRADD(codePageStart, sizeof(code)), pagesize);

	#ifdef EZ_TARGET_WINDOWS
	DWORD oldProtect;
	if(!VirtualProtect(codePageStart,
		PTRDIFF(codePageEnd, codePageStart),
		PAGE_EXECUTE_READWRITE,
		&oldProtect
	)){
		PERROR("VirtualProtect");
		return -1;
	}
	#else
	if(mprotect(codePageStart,
		PTRDIFF(codePageEnd, codePageStart),
		PROT_READ | PROT_WRITE | PROT_EXEC
	) < 0){
        PERROR("mprotect");
		return -1;
    }
	#endif

	struct inj_unload_call *call = &unload_call;

	call->lib_handle = crt_userlib_handle;
	#ifdef EZ_TARGET_WINDOWS
	call->FreeLibrary = &FreeLibrary;
	call->ExitThread = &ExitThread;
	call->SetEvent = &SetEvent;
	call->VirtualProtect = &VirtualProtect;
	call->WaitForSingleObject = &WaitForSingleObject;
	call->CloseHandle = &CloseHandle;
	call->caller_thread = OpenThread(SYNCHRONIZE, FALSE, GetCurrentThreadId());
	call->cond = CreateEvent(NULL, TRUE, FALSE, NULL);
	#else
	call->dlclose = &dlclose;
	call->pthread_exit = &pthread_exit;
	call->pthread_mutex_lock = &pthread_mutex_lock;
	call->pthread_mutex_unlock = &pthread_mutex_unlock;
	call->pthread_cond_wait = &pthread_cond_wait;
	call->pthread_cond_signal = &pthread_cond_signal;
	call->pthread_join = &pthread_join;
	call->mprotect = &mprotect;
	call->caller_thread = pthread_self();
	pthread_mutex_init(&call->mutex, NULL);
	pthread_cond_init(&call->cond, NULL);
	#endif
	call->memcpy = &memcpy;
	call->code = code;
	call->code_size = code_size;
	call->pagesize = pagesize;

	off_t stage2_offset = PTRDIFF(&crt_inj_unload2, region_crtpl_code.start);
	call->stage2_offset = stage2_offset;

    void *pfnUnload = (void *)PTRADD(
        code,
        PTRDIFF(&crt_inj_unload, region_crtpl_code.start)
    );
#if defined(EZ_TARGET_POSIX)
	pthread_t tid;
	pthread_create(&tid, NULL, (void*(*)(void *))pfnUnload, call);
	pthread_detach(tid);

	pthread_mutex_lock(&call->mutex);
	while(!call->relocated){
		pthread_cond_wait(&call->cond, &call->mutex);
	}
	pthread_mutex_unlock(&call->mutex);
#elif defined(EZ_TARGET_WINDOWS)
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pfnUnload, NULL, 0, NULL);
	WaitForSingleObject(call->cond, INFINITE);
#endif

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
