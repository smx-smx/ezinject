/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <windows.h>
#include <inttypes.h>
#include "ezinject.h"
#include "crt.h"
#include "log.h"

EZAPI crt_thread_create(struct injcode_bearing *br, crt_thread_func_t pfnThreadEntry){
	DWORD dwThreadId;
	HANDLE hThread = CreateThread(
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)pfnThreadEntry,
		br,
		0,
		&dwThreadId
	);
	br->hThread = hThread;
	br->user_tid = dwThreadId;
	DBG("tid: %"PRIdMAX, br->user_tid);

	if(hThread == NULL || hThread == INVALID_HANDLE_VALUE){
		PERROR("CreateThread");
		return -1;
	}
	return 0;
}

EZAPI crt_thread_notify(struct injcode_bearing *br){
	if(SetEvent(br->hEvent) == FALSE){
		PERROR("SetEvent");
		return -1;
	}
	return 0;
}
