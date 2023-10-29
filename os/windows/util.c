/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include <windows.h>
#include <psapi.h>
#include <shlwapi.h>
#include <TlHelp32.h>

#include "ezinject_common.h"
#include "log.h"

BOOL win32_errstr(DWORD dwErrorCode, LPTSTR pBuffer, DWORD cchBufferLength){
	if(cchBufferLength == 0){
		return FALSE;
	}

	DWORD cchMsg = FormatMessage(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dwErrorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		pBuffer,
		cchBufferLength,
		NULL
	);

	if(cchMsg > 0){
		char *nl = strrchr(pBuffer, '\n');
		if(nl){
			*nl = '\0';
			if(*(nl-1) == '\r'){
				*(nl - 1) = '\0';
			}
		}
		return TRUE;
	}

	return FALSE;
}

char *strcasestr(const char *s, const char *find) {
	char c, sc;
	size_t len;

	if ((c = *find++) != 0) {
		c = tolower((unsigned char)c);
		len = strlen(find);
		do {
			do {
				if ((sc = *s++) == 0)
					return (NULL);
			} while ((char)tolower((unsigned char)sc) != c);
		} while (strncasecmp(s, find, len) != 0);
		s--;
	}
	return ((char *)s);
}

void *get_base(pid_t pid, char *substr, char **ignores) {
	UNUSED(ignores);

	HANDLE hProcess = INVALID_HANDLE_VALUE;

	hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
                            PROCESS_VM_READ,
                            FALSE, pid );
	if (NULL == hProcess){
		ERR("OpenProcess() failed");
		return NULL;
	}

	void *base = NULL;
	HANDLE hSnap = INVALID_HANDLE_VALUE;
	TCHAR *imageFileName = NULL;
	do {
		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
		if(hSnap == INVALID_HANDLE_VALUE){
			PERROR("CreateToolhelp32Snapshot failed");
			break;
		}

		MODULEENTRY32 mod32 = {
			.dwSize = sizeof(MODULEENTRY32)
		};

		if(!Module32First(hSnap, &mod32)){
			PERROR("Module32First");
			break;
		}

		imageFileName = mod32.szExePath;
		DBG("imageFileName: %s", imageFileName);

		do {
			TCHAR *modName = mod32.szModule;
			uintptr_t modBase = (uintptr_t)mod32.modBaseAddr;
			DBG("%p -> %s", (void *)modBase, modName);

			if(
				(substr == NULL && !_stricmp(imageFileName, modName)) ||
				(substr != NULL && strcasestr(modName, substr) != NULL)
			){
				base = (void *)modBase;
				break;
			}

		} while(Module32Next(hSnap, &mod32));

	} while(0);
	if(imageFileName != NULL){
		free(imageFileName);
	}
	if(hSnap != INVALID_HANDLE_VALUE){
		CloseHandle(hSnap);
	}
	CloseHandle(hProcess);

	return base;
}
