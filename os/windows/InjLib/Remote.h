#ifndef __REMOTE_H__
#define __REMOTE_H__

#include <windows.h>
#include <tlhelp32.h>
#include "struct.h"

// Ordinal of Kernel32.GDIReallyCares()
#define GDIREALLYCARES_ORDINAL 0x17     // 23
// Ordinal of Kernel32.IsThreadId()
#define ISTHREADID_ORDINAL      0x47    // 71
// Ordinal of Kernel32.GetpWin16Lock()
#define GETPWIN16LOCK_ORDINAL  0x5D     // 93
// Ordinal of Kernel32.EnterSysLevel()
#define ENTERSYSLEVEL_ORDINAL  0x61     // 97
// Ordinal of Kernel32.LeaveSysLevel()
#define LEAVESYSLEVEL_ORDINAL  0x62     // 98

// Buffer argument passed to NtCreateThreadEx function
typedef struct _NTCREATETHREADEXBUFFER
 {
   ULONG  Size;
   ULONG  Unknown1;
   ULONG  Unknown2;
   PULONG Unknown3;
   ULONG  Unknown4;
   ULONG  Unknown5;
   ULONG  Unknown6;
   PULONG Unknown7;
   ULONG  Unknown8;
 } NTCREATETHREADEXBUFFER;

typedef DWORD (WINAPI *PFNTCREATETHREADEX)
( 
    PHANDLE                 ThreadHandle,	
    ACCESS_MASK             DesiredAccess,	
    LPVOID                  ObjectAttributes,	
    HANDLE                  ProcessHandle,	
    LPTHREAD_START_ROUTINE  lpStartAddress,	
    LPVOID                  lpParameter,	
    BOOL	                CreateSuspended,	
    DWORD                   dwStackSize,	
    DWORD                   dw1, 
    DWORD                   dw2, 
    LPVOID                  Unknown 
); 

// System functions loaded dinamically
typedef VOID (NTAPI *LDRSHUTDOWNTHREAD)();
typedef ULONG (NTAPI *RTLNTSTATUSTODOSERROR)(NTSTATUS);
typedef NTSTATUS (NTAPI *RTLCREATEUSERTHREAD)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, PULONG, PULONG, PVOID, PVOID, PHANDLE, PCLIENT_ID);
typedef NTSTATUS (NTAPI *NTALLOCATEVIRTUALMEMORY)(HANDLE, PVOID*, ULONG, ULONG*, ULONG, ULONG);
typedef NTSTATUS (NTAPI *NTFREEVIRTUALMEMORY)(HANDLE, PVOID*, ULONG*, ULONG);
typedef NTSTATUS (NTAPI *NTOPENTHREAD)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS (NTAPI *NTQUERYINFORMATIONPROCESS)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NTQUERYINFORMATIONTHREAD)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NTQUEUEAPCTHREAD)(HANDLE, PKNORMAL_ROUTINE, PVOID, PVOID, PVOID);
typedef NTSTATUS (NTAPI *NTTERMINATETHREAD)(HANDLE, NTSTATUS);
typedef NTSTATUS (NTAPI *NTCREATETHREADEX)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, ULONG, ULONG, ULONG, ULONG, LPVOID);
typedef LONG (NTAPI *NTQUERYSYSTEMINFORMATION)(UINT, PVOID, ULONG, PULONG);
typedef HANDLE (WINAPI *CREATETOOLHELP32SNAPSHOT)(DWORD, DWORD);
typedef BOOL (WINAPI *THREAD32FIRST)(HANDLE, LPTHREADENTRY32);
typedef BOOL (WINAPI *THREAD32NEXT)(HANDLE, LPTHREADENTRY32);
typedef HANDLE (WINAPI *OPENTHREAD)(DWORD, BOOL, DWORD);
typedef DWORD (WINAPI *GETPROCESSID)(HANDLE);
typedef DWORD (WINAPI *GETTHREADID)(HANDLE);
typedef LPVOID (WINAPI *VIRTUALALLOCEX)(HANDLE, LPVOID, DWORD, DWORD, DWORD);
typedef BOOL (WINAPI *VIRTUALFREEEX)(HANDLE, LPVOID, DWORD, DWORD);
typedef HANDLE (WINAPI *CREATEREMOTETHREAD)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *ISTHREADID)(DWORD);
typedef VOID (WINAPI *GETPWIN16LOCK)(DWORD *pWin16Lock);
typedef VOID (WINAPI *ENTERSYSLEVEL)(DWORD lock);
typedef VOID (WINAPI *LEAVESYSLEVEL)(DWORD lock);

// Internal Kernel32 functions
typedef PVOID (WINAPI *INTERNALCREATEREMOTETHREAD)(PVOID, DWORD, LPTHREAD_START_ROUTINE, LPVOID, DWORD);
typedef HANDLE (WINAPI *INTERNALOPENTHREAD)(DWORD, BOOL, DWORD);

// Pointer to internal data structures
// (must be casted depending on Windows version)
typedef PVOID PTIB;
typedef PVOID PPDB;
typedef PVOID PTDB;

#define CREATE_SILENT   0x80000000  // dwCreationFlags bit for CreateRemoteThread()
                                    // (Signals that Win9x process not initialized)
#ifdef REMOTE_DEFINE_GLOBALS
#define REMOTE_EXTERN 
#else
#define REMOTE_EXTERN extern
#endif

// Global variables
REMOTE_EXTERN int     OSMajorVersion, OSMinorVersion, OSBuildVersion;
REMOTE_EXTERN BOOL    OSWin9x, OSWin95, OSWin98, OSWinMe;
REMOTE_EXTERN BOOL    OSWinNT, OSWinNT3_2003, OSWinVista_7;
REMOTE_EXTERN DWORD   dwObsfucator;               // Win 9x obfuscator
REMOTE_EXTERN IMTE    **pMTEModTable;             // Global IMTE table
REMOTE_EXTERN DWORD   Win16Mutex;                 // Win16Mutex
REMOTE_EXTERN DWORD   Krn32Mutex;                 // Krn32Mutex

// NOTE: Cannot use the original Kernel32 functions names because of VC++ implicit linking.
REMOTE_EXTERN OPENTHREAD                  K32_OpenThread;
REMOTE_EXTERN GETPROCESSID                K32_GetProcessId;
REMOTE_EXTERN GETTHREADID                 K32_GetThreadId;
REMOTE_EXTERN VIRTUALALLOCEX              K32_VirtualAllocEx;
REMOTE_EXTERN VIRTUALFREEEX               K32_VirtualFreeEx;
REMOTE_EXTERN CREATEREMOTETHREAD          K32_CreateRemoteThread;
REMOTE_EXTERN CREATETOOLHELP32SNAPSHOT    K32_CreateToolhelp32Snapshot;
REMOTE_EXTERN THREAD32FIRST               K32_Thread32First;
REMOTE_EXTERN THREAD32NEXT                K32_Thread32Next;

REMOTE_EXTERN LDRSHUTDOWNTHREAD           LdrShutdownThread;
REMOTE_EXTERN RTLNTSTATUSTODOSERROR       RtlNtStatusToDosError;
REMOTE_EXTERN RTLCREATEUSERTHREAD         RtlCreateUserThread;
REMOTE_EXTERN NTALLOCATEVIRTUALMEMORY     NtAllocateVirtualMemory;
REMOTE_EXTERN NTFREEVIRTUALMEMORY         NtFreeVirtualMemory;
REMOTE_EXTERN NTOPENTHREAD                NtOpenThread;
REMOTE_EXTERN NTQUERYINFORMATIONPROCESS   NtQueryInformationProcess;
REMOTE_EXTERN NTQUERYINFORMATIONTHREAD    NtQueryInformationThread;
REMOTE_EXTERN NTQUERYSYSTEMINFORMATION    NtQuerySystemInformation;
REMOTE_EXTERN NTQUEUEAPCTHREAD            NtQueueApcThread;
REMOTE_EXTERN NTTERMINATETHREAD           NtTerminateThread;
REMOTE_EXTERN NTCREATETHREADEX            NtCreateThreadEx;
REMOTE_EXTERN GETPWIN16LOCK               GetpWin16Lock;
REMOTE_EXTERN ENTERSYSLEVEL               EnterSysLevel;
REMOTE_EXTERN LEAVESYSLEVEL               LeaveSysLevel;
REMOTE_EXTERN ISTHREADID                  IsThreadId;
REMOTE_EXTERN INTERNALCREATEREMOTETHREAD  InternalCreateRemoteThread;
REMOTE_EXTERN INTERNALOPENTHREAD          InternalOpenThread;

// Functions declaration
PTIB GetTIB();
PTDB GetTDB(DWORD TID);
PPDB GetPDB(DWORD PID);
DWORD GetObsfucator();
LPVOID _VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, DWORD dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL _VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, DWORD dwSize, DWORD dwFreeType);
HANDLE _OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
DWORD _GetProcessId(HANDLE hProcess);
DWORD _GetThreadId(HANDLE hThread);
HANDLE _CreateRemoteThread(HANDLE hProcess,
                           LPSECURITY_ATTRIBUTES   lpThreadAttributes,
                           DWORD                   dwStackSize,
                           LPTHREAD_START_ROUTINE  lpStartAddress,
                           LPVOID                  lpParameter,
                           DWORD                   dwCreationFlags,
                           LPDWORD                 lpThreadId);
DWORD _GetProcessThread(DWORD dwPID);
BOOL Initialization();

#endif  // __REMOTE_H__
