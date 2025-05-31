/*
 * Copyright (C) 2025 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include "crt_injcode.h"
#include <pthread.h>
#include <signal.h>

#include "ezinject.h"

#ifdef memcpy
#undef memcpy
#endif

void CPLAPI crt_inj_unload2(struct inj_unload_call *call, struct inj_unload_call *parent){
    // wait for the caller thread to perform cleanup and exit
#ifdef EZ_TARGET_WINDOWS
    call->SetEvent(parent->cond);
    call->WaitForSingleObject(call->caller_thread, INFINITE);
    call->CloseHandle(call->caller_thread);
    call->FreeLibrary(call->lib_handle);
    call->ExitThread(0);
#else
	call->pthread_mutex_lock(&parent->mutex);
	{
		parent->relocated = true;
		call->pthread_cond_signal(&parent->cond);
	}
	call->pthread_mutex_unlock(&parent->mutex);
    call->pthread_join(call->caller_thread, NULL);
    call->dlclose(call->lib_handle);
    call->pthread_exit(NULL);
#endif
    for(;;);
}

void CPLAPI crt_inj_unload(struct inj_unload_call *call_req){
    /** copy arguments and code to our stack */
    struct inj_unload_call call_local;
    call_req->memcpy(&call_local, call_req, sizeof(*call_req));
    struct inj_unload_call *call = &call_local;

    uint8_t code[call->code_size];
    call->memcpy(code, call->code, call->code_size);

    void *codePageStart = ALIGN_DOWN(&code, call->pagesize);
	void *codePageEnd = ALIGN(PTRADD(codePageStart, call->code_size), call->pagesize);

    #ifdef EZ_TARGET_WINDOWS
    DWORD oldProtect;
    if(!call->VirtualProtect(codePageStart,
        PTRDIFF(codePageEnd, codePageStart),
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    )){
        return;
    }
    #else
    if(call->mprotect(codePageStart,
		PTRDIFF(codePageEnd, codePageStart),
		PROT_READ | PROT_WRITE | PROT_EXEC
	) < 0){
        return;
    }
    #endif

    void (*stage2)(struct inj_unload_call *, struct inj_unload_call *) = (void *)(&code[call->stage2_offset]);
    // should never return
    stage2(call, call_req);
}

