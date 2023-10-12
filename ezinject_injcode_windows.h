/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */

#ifndef __EZINJECT_INJCODE_WINDOWS_H
#define __EZINJECT_INJCODE_WINDOWS_H

#include <windows.h>

struct dl_api {
	/** LoadLibraryA **/
	void *(WINAPI *dlopen)(const char *filename);
	/** GetProcAddress **/
	void *(WINAPI *dlsym)(void *handle, const char *symbol);
	/** FreeLibrary **/
	int (WINAPI *dlclose)(void *handle);
	/** always NULL **/
	char *(*dlerror)(void);
};

struct thread_api {
	HANDLE (WINAPI *CreateEventA)(
		LPSECURITY_ATTRIBUTES lpEventAttributes,
		BOOL                  bManualReset,
		BOOL                  bInitialState,
		LPCSTR                lpName
	);
	HANDLE (WINAPI *CreateThread)(
		LPSECURITY_ATTRIBUTES   lpThreadAttributes,
		SIZE_T                  dwStackSize,
		LPTHREAD_START_ROUTINE  lpStartAddress,
		__drv_aliasesMem LPVOID lpParameter,
		DWORD                   dwCreationFlags,
		LPDWORD                 lpThreadId
	);
	BOOL (WINAPI *CloseHandle)(
  		HANDLE hObject
	);
	DWORD (WINAPI *WaitForSingleObject)(
		HANDLE hHandle,
		DWORD  dwMilliseconds
	);
	BOOL (WINAPI *GetExitCodeThread)(
		HANDLE  hThread,
		LPDWORD lpExitCode
	);
};

#endif
