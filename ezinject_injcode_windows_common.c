/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
struct dl_api {
	/** LoadLibraryA **/
	void *(*dlopen)(const char *filename);
	/** GetProcAddress **/
	void *(*dlsym)(void *handle, const char *symbol);
	/** FreeLibrary **/
	int (*dlclose)(void *handle);
	/** always NULL **/
	char *(*dlerror)(void);
};

struct thread_api {
	HANDLE (*CreateEventA)(
		LPSECURITY_ATTRIBUTES lpEventAttributes,
		BOOL                  bManualReset,
		BOOL                  bInitialState,
		LPCSTR                lpName
	);
	HANDLE (*CreateThread)(
		LPSECURITY_ATTRIBUTES   lpThreadAttributes,
		SIZE_T                  dwStackSize,
		LPTHREAD_START_ROUTINE  lpStartAddress,
		__drv_aliasesMem LPVOID lpParameter,
		DWORD                   dwCreationFlags,
		LPDWORD                 lpThreadId
	);
	BOOL (*CloseHandle)(
  		HANDLE hObject
	);
	DWORD (*WaitForSingleObject)(
		HANDLE hHandle,
		DWORD  dwMilliseconds
	);
	BOOL (*GetExitCodeThread)(
		HANDLE  hThread,
		LPDWORD lpExitCode
	);
};

INLINE void inj_puts(struct injcode_bearing *br, char *str){
	if(str == NULL){
		return;
	}

	PPEB peb = br->RtlGetCurrentPeb();
	PINT_RTL_USER_PROCESS_PARAMETERS params = (PINT_RTL_USER_PROCESS_PARAMETERS)peb->ProcessParameters;
	
	HANDLE h = params->StandardOutput;
	if(h == INVALID_HANDLE_VALUE){
		return;
	}

	int l = 0;
	char *p = str;
	while(*(p++)) ++l;

	IO_STATUS_BLOCK stb;
	br->NtWriteFile(h, NULL, NULL, NULL, &stb, str, l, 0, NULL);

	char nl[2];
	nl[0] = '\r'; nl[1] = '\n';
	br->NtWriteFile(h, NULL, NULL, NULL, &stb, nl, sizeof(nl), 0, NULL);
}
