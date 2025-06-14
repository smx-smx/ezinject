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
#include <tlhelp32.h>

#include "ezinject.h"
#include "dlfcn_compat.h"
#include "log.h"
#include "util.h"

/** WinNT API */
NTSTATUS NTAPI (*pfnRtlQueryProcessDebugInformation)(
	HANDLE UniqueProcessId,
	ULONG Flags,
	PRTL_DEBUG_INFORMATION Buffer
) = NULL;
PRTL_DEBUG_INFORMATION NTAPI (*pfnRtlCreateQueryDebugBuffer)(ULONG Size, BOOLEAN EventPair) = NULL;
NTSTATUS NTAPI (*pfnRtlDestroyQueryDebugBuffer)(PRTL_DEBUG_INFORMATION Buffer) = NULL;

/** Win32 API */
HANDLE WINAPI (*pfnCreateToolhelp32Snapshot)(DWORD dwFlags,DWORD th32ProcessID) = NULL;
BOOL WINAPI (*pfnModule32First)(HANDLE hSnapshot, LPMODULEENTRY32 lpme) = NULL;
BOOL WINAPI (*pfnModule32Next)(HANDLE hSnapshot, LPMODULEENTRY32 lpme) = NULL;

static EZAPI _win32_init_process_apis(OSVERSIONINFO *osvi){
	/** init APIs for get_base */
	if(osvi->dwPlatformId == VER_PLATFORM_WIN32_NT){
		HMODULE ntdll = GetModuleHandle("ntdll.dll");
		pfnRtlQueryProcessDebugInformation = LIB_GETSYM(ntdll, "RtlQueryProcessDebugInformation");
		pfnRtlCreateQueryDebugBuffer = LIB_GETSYM(ntdll, "RtlCreateQueryDebugBuffer");
		pfnRtlDestroyQueryDebugBuffer = LIB_GETSYM(ntdll, "RtlDestroyQueryDebugBuffer");
		DBGPTR(pfnRtlQueryProcessDebugInformation);
		DBGPTR(pfnRtlCreateQueryDebugBuffer);
		DBGPTR(pfnRtlDestroyQueryDebugBuffer);
		if(!pfnRtlQueryProcessDebugInformation || !pfnRtlCreateQueryDebugBuffer || !pfnRtlDestroyQueryDebugBuffer){
			ERR("Failed to resolve Windows NT APIs");
			return -1;
		}
	} else {
		HMODULE hKernel32 = GetModuleHandle("kernel32.dll");
		if(!hKernel32){
			PERROR("GetModuleHandle");
			return -1;
		}
		pfnCreateToolhelp32Snapshot = LIB_GETSYM(hKernel32, "CreateToolhelp32Snapshot");
		pfnModule32First = LIB_GETSYM(hKernel32, "Module32First");
		pfnModule32Next = LIB_GETSYM(hKernel32, "Module32Next");
		DBGPTR(pfnCreateToolhelp32Snapshot);
		DBGPTR(pfnModule32First);
		DBGPTR(pfnModule32Next);
		if(!pfnCreateToolhelp32Snapshot || !pfnModule32First || !pfnModule32Next){
			ERR("Failed to resolve ToolHelp APIs");
			return -1;
		}
	}
	return 0;
}

EZAPI os_api_init(struct ezinj_ctx *ctx){
	OSVERSIONINFO osvi = {
		.dwOSVersionInfoSize = sizeof(osvi)
	};
	if(!GetVersionEx(&osvi)) {
		PERROR("GetVersionEx");
		return -1;
	}
	if(_win32_init_process_apis(&osvi) < 0){
		ERR("_win32_init_process_apis() failed");
		return -1;
	}
	return 0;
}

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

static uintptr_t _search_executable_region(HANDLE hProcess, LPVOID baseAddr){
	MEMORY_BASIC_INFORMATION mbi;
	SYSTEM_INFO si;
	GetSystemInfo(&si);

	BOOL found = FALSE;
	LPVOID lpMem = baseAddr;
	do {
		if(VirtualQueryEx(hProcess, lpMem, &mbi, sizeof(mbi)) == 0){
			PERROR("VirtualQueryEx");
			break;
		}
		DBGPTR(lpMem);
		DBG("mem protection: %"PRIuMAX, (uintmax_t)mbi.Protect);

		if(mbi.Type != MEM_IMAGE) goto next;
		if((mbi.Protect & PAGE_NOACCESS)) goto next;
		if((mbi.Protect & PAGE_GUARD)) goto next;
		if((mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_EXECUTE_READWRITE)){
			found = TRUE;
			break;
		}

		next:
		lpMem = VPTR(UPTR(lpMem) + mbi.RegionSize);
	} while(lpMem < si.lpMaximumApplicationAddress);

	return (found) ? UPTR(lpMem) : 0;
}

static void *get_base_winnt(pid_t pid, const char *substr, const char **ignores) {
	HANDLE hProcess = INVALID_HANDLE_VALUE;


	DBG("pid: %"PRIdMAX", substr: %s", (intmax_t)pid, substr);
	hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
                            PROCESS_VM_READ,
                            FALSE, pid );
	if (NULL == hProcess){
		PERROR("OpenProcess");
		return NULL;
	}

	void *base = NULL;
	do {
		PRTL_DEBUG_INFORMATION debugBuffer = pfnRtlCreateQueryDebugBuffer(0, FALSE);
		if(!debugBuffer){
			PERROR("RtlCreateQueryDebugBuffer");
			break;
		}

		pfnRtlQueryProcessDebugInformation((HANDLE)pid, RTL_DEBUG_QUERY_MODULES, debugBuffer);

		DBG("number of modules: %"PRIuMAX, (uintmax_t)debugBuffer->Modules->NumberOfModules);
		for(unsigned i=0; i<debugBuffer->Modules->NumberOfModules; i++){
			PRTL_PROCESS_MODULE_INFORMATION mod = &debugBuffer->Modules->Modules[i];
			char *imageFileName = mod->FullPathName;
			DBG("imageFileName: %s", imageFileName);
			{
				char *backslash = strrchr(imageFileName, '\\');
				if(backslash != NULL){
					imageFileName = backslash + 1;
				}
			}
			DBG("imageBaseName: %s", imageFileName);

			char *lastdot = strrchr(imageFileName, '.');
			if(lastdot == NULL) continue;

			for(char *t = lastdot; *t != '\0'; t++){
				*t = tolower(*t);
			}

			if(substr == NULL){
				if(!strcmp(lastdot, ".exe")){
					base = (LPVOID)_search_executable_region(hProcess, (LPVOID)mod->ImageBase);
				}
			} else if(strcasestr(imageFileName, substr) != NULL){
				base = (LPVOID)mod->ImageBase;
			}
		}

		pfnRtlDestroyQueryDebugBuffer(debugBuffer);
	} while(0);
	CloseHandle(hProcess);

	return base;
}

static void *get_base_toolhelp(pid_t pid, const char *substr, const char **ignores){
	UNUSED(ignores);

	HANDLE hProcess = INVALID_HANDLE_VALUE;

	OSVERSIONINFO osvi = {
		.dwOSVersionInfoSize = sizeof(OSVERSIONINFO)
	};
	if (!GetVersionEx(&osvi)){
		PERROR("GetVersionEx");
		return NULL;
	}
	BOOL isWINNT = osvi.dwPlatformId == VER_PLATFORM_WIN32_NT;

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
		hSnap = pfnCreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
		if(hSnap == INVALID_HANDLE_VALUE){
			PERROR("CreateToolhelp32Snapshot failed");
			break;
		}

		MODULEENTRY32 mod32 = {
			.dwSize = sizeof(MODULEENTRY32)
		};

		if(!pfnModule32First(hSnap, &mod32)){
			PERROR("Module32First");
			break;
		}

		imageFileName = mod32.szExePath;
		DBG("imageFileName: %s", imageFileName);
		{
			char *backslash = strrchr(imageFileName, '\\');
			if(backslash != NULL){
				imageFileName = backslash + 1;
			}
		}
		DBG("imageFileName: %s", imageFileName);
		do {
			TCHAR *modName = mod32.szModule;
			uintptr_t modBase = (uintptr_t)mod32.modBaseAddr;
			DBG("%p -> %s", (void *)modBase, modName);

			if(substr == NULL){
				if(!_stricmp(imageFileName, modName)){
					if(isWINNT){
						base = (LPVOID)_search_executable_region(hProcess, (LPVOID)modBase);
					} else {
						base = (LPVOID)modBase;
					}
					break;
				}
			} else if(strcasestr(modName, substr) != NULL){
				base = (void *)modBase;
				break;
			}
		} while(pfnModule32Next(hSnap, &mod32));

	} while(0);
	if(imageFileName != NULL){
		free(imageFileName);
	}
	if(hSnap != INVALID_HANDLE_VALUE){
		CloseHandle(hSnap);
	}
	CloseHandle(hProcess);

	DBG("base for %s -> %p", substr, base);
	return base;
}

void *get_base(struct ezinj_ctx *ctx, pid_t pid, const char *substr, const char **ignores) {
	OSVERSIONINFO osvi = {
		.dwOSVersionInfoSize = sizeof(osvi)
	};
	if(!GetVersionEx(&osvi)) {
		PERROR("GetVersionEx");
		return NULL;
	}
	if(osvi.dwPlatformId == VER_PLATFORM_WIN32_NT){
		return get_base_winnt(pid, substr, ignores);
	} else {
		return get_base_toolhelp(pid, substr, ignores);
	}
}

char *os_realpath(const char *path){
	DWORD nChars = GetFullPathNameA(path, 0, NULL, NULL);
	if(nChars == 0){
		PERROR("GetFullPathNameA");
		return NULL;
	}
	char *buffer = malloc(nChars + 1);
	buffer[nChars] = '\0';
	if(GetFullPathNameA(path, nChars, buffer, NULL) == 0){
		PERROR("GetFullPathNameA");
		free(buffer);
		return NULL;
	}
	return buffer;
}