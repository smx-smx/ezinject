/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#ifndef __WINDOWS_UTIL_H
#define __WINDOWS_UTIL_H

#include <windows.h>
BOOL win32_errstr(DWORD dwErrorCode, LPTSTR pBuffer, DWORD cchBufferLength);

//
// RTL Debug Queries
//
#define RTL_DEBUG_QUERY_MODULES     0x01
#define RTL_DEBUG_QUERY_BACKTRACES  0x02
#define RTL_DEBUG_QUERY_HEAPS       0x04
#define RTL_DEBUG_QUERY_HEAP_TAGS   0x08
#define RTL_DEBUG_QUERY_HEAP_BLOCKS 0x10
#define RTL_DEBUG_QUERY_LOCKS       0x20

//
// Information Structures for RTL Debug Functions
//

// Module information

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

// private
typedef struct _RTL_PROCESS_MODULE_INFORMATION_EX
{
    USHORT NextOffset;
    RTL_PROCESS_MODULE_INFORMATION BaseInfo;
    ULONG ImageChecksum;
    ULONG TimeDateStamp;
    PVOID DefaultBase;
} RTL_PROCESS_MODULE_INFORMATION_EX, *PRTL_PROCESS_MODULE_INFORMATION_EX;

typedef struct _RTL_DEBUG_INFORMATION
{
	HANDLE SectionHandleClient;
	PVOID ViewBaseClient;
	PVOID ViewBaseTarget;
	ULONG ViewBaseDelta;
	HANDLE EventPairClient;
	PVOID EventPairTarget;
	HANDLE TargetProcessId;
	HANDLE TargetThreadHandle;
	ULONG Flags;
	ULONG OffsetFree;
	ULONG CommitSize;
	ULONG ViewSize;
	union
	{
		PRTL_PROCESS_MODULES Modules;
		LPVOID/*PRTL_PROCESS_MODULE_INFORMATION_EX*/ ModulesEx;
	};
	LPVOID/*PRTL_PROCESS_BACKTRACES*/ BackTraces;
	LPVOID/*PRTL_PROCESS_HEAPS*/ Heaps;
	LPVOID/*PRTL_PROCESS_LOCKS*/ Locks;
	HANDLE SpecificHeap;
	HANDLE TargetProcessHandle;
	LPVOID/*RTL_PROCESS_VERIFIER_OPTIONS*/ VerifierOptions;
	HANDLE ProcessHeap;
	HANDLE CriticalSectionHandle;
	HANDLE CriticalSectionOwnerThread;
	PVOID Reserved[4];
} RTL_DEBUG_INFORMATION, *PRTL_DEBUG_INFORMATION;

extern NTSTATUS NTAPI (*RtlQueryProcessDebugInformation)(
	HANDLE UniqueProcessId,
	ULONG Flags,
	PRTL_DEBUG_INFORMATION Buffer
);
extern PRTL_DEBUG_INFORMATION NTAPI (*RtlCreateQueryDebugBuffer)(ULONG Size, BOOLEAN EventPair);
extern NTSTATUS NTAPI (*RtlDestroyQueryDebugBuffer)(PRTL_DEBUG_INFORMATION Buffer);

#endif
