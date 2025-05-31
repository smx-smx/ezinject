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

#if defined(EZ_TARGET_POSIX)
#include <sys/mman.h>
#elif defined(EZ_TARGET_WINDOWS)
#include <windows.h>
#endif
struct inj_unload_call {
#if defined(EZ_TARGET_POSIX)
    pthread_t caller_thread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int (*dlclose)(void *handle);
    void (*pthread_exit)(void *retval);
    int (*pthread_mutex_lock)(pthread_mutex_t *mutex);
	int (*pthread_mutex_unlock)(pthread_mutex_t *mutex);
    int (*pthread_cond_wait)(pthread_cond_t *restrict cond, pthread_mutex_t *restrict mutex);
    int (*pthread_join)(pthread_t thread, void **value_ptr);
    int (*pthread_cond_signal)(pthread_cond_t *cond);
    int (*mprotect)(void *addr, size_t size, int prot);
#elif defined(EZ_TARGET_WINDOWS)
    HANDLE caller_thread;
    HANDLE cond;
    BOOL (*CloseHandle)(HANDLE hObject);
    DWORD (*WaitForSingleObject)(
        HANDLE hHandle,
        DWORD  dwMilliseconds
    );
    WINBOOL WINAPI (*FreeLibrary)(HMODULE hLibModule);
    VOID WINAPI (*ExitThread)(DWORD dwExitCode);
    BOOL (*SetEvent)(HANDLE hEvent);
    BOOL (*VirtualProtect)(
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flNewProtect,
        PDWORD lpflOldProtect
    );
#endif
    void *(*memcpy)(void *destination, const void *source, size_t num);
    bool relocated;
    void *lib_handle;
    uint8_t *code;
    size_t code_size;
    off_t stage2_offset;
    size_t pagesize;
};

void CPLAPI crt_inj_unload(struct inj_unload_call *call);
void CPLAPI crt_inj_unload2(struct inj_unload_call *call, struct inj_unload_call *parent);

#endif
