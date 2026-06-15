#ifndef __EZINJECT_INJCODE_PLATFORM_WINDOWS_H
#define __EZINJECT_INJCODE_PLATFORM_WINDOWS_H

struct bearing_platform {
	HANDLE hThread;
	HANDLE hEvent;
	NTSTATUS NTAPI (*libc_dlopen)(
		PWSTR SearchPath,
		PULONG DllCharacteristics,
		PUNICODE_STRING DllName,
		PVOID *BaseAddress
	);
	HANDLE WINAPI (*CreateFileA)(
		LPCSTR                lpFileName,
		DWORD                 dwDesiredAccess,
		DWORD                 dwShareMode,
		LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		DWORD                 dwCreationDisposition,
		DWORD                 dwFlagsAndAttributes,
		HANDLE                hTemplateFile
	);
	WINBOOL WINAPI (*WriteFile)(
		HANDLE       hFile,
		LPCVOID      lpBuffer,
		DWORD        nNumberOfBytesToWrite,
		LPDWORD      lpNumberOfBytesWritten,
		LPOVERLAPPED lpOverlapped
	);
	WINBOOL (*CloseHandle)(HANDLE hObject);
	NTSTATUS NTAPI (*LdrRegisterDllNotification)(
		ULONG   Flags,
		PVOID	NotificationFunction,
		PVOID   Context,
		PVOID   *Cookie
	);
	NTSTATUS NTAPI (*LdrUnregisterDllNotification)(PVOID Cookie);
	WINBOOL WINAPI (*AllocConsole)(void);
	uintptr_t ntdll_base;
	uintptr_t kernel32_base;
};

struct call_platform {
	LPVOID WINAPI (*VirtualAlloc)(
		LPVOID lpAddress,
		SIZE_T dwSize,
		DWORD flAllocationType,
		DWORD flProtect
	);
	WINBOOL WINAPI (*VirtualFree)(
		LPVOID lpAddress,
		SIZE_T dwSize,
		DWORD dwFreeType
	);
	DWORD WINAPI (*SuspendThread)(HANDLE hThread);
	HANDLE WINAPI (*GetCurrentThread)(VOID);
};

#endif
