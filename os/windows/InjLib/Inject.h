#ifndef __INJECT_H__
#define __INJECT_H__

#if _MSC_VER > 1000
    #pragma once
#endif

#ifdef DLL_EXPORT
    #define DLL_IMP_EXP __declspec(dllexport)
#else
    #define DLL_IMP_EXP __declspec(dllimport)
#endif

#ifdef __cplusplus
  extern "C" {
#endif

// Process flags returned by GetProcessInfo()
#define fWIN9X               0x00000001  // Win 9x process
#define fWINNT               0x00000002  // Win NT process
#define fINVALID             0x00000004  // Invalid process
#define fDEBUGGED            0x00000008  // Process is being debugged
#define fNOTINITIALIZED      0x00000010  // Not initialized process
#define fPROTECTED           0x00000020  // Protected process

// Local/remote exception
#define LOCAL_EXCEPTION      0x20000000
#define REMOTE_EXCEPTION     0x10000000

// Error codes
#define    ERROR_OK                         0
#define    ERROR_REMOTE                     1
#define    ERROR_INVALIDOS                  2
#define    ERROR_EXCEPTION                  3
#define    ERROR_INVALIDPROCESS             4
#define    ERROR_WAITTIMEOUT                5
#define    ERROR_OPENPROCESS                6
#define    ERROR_READPROCESSMEMORY          7
#define    ERROR_WRITEPROCESSMEMORY         8
#define    ERROR_VIRTUALALLOCEX             9
#define    ERROR_NTQUERYINFORMATIONPROCESS  10
#define    ERROR_CREATETHREAD               11
#define    ERROR_RTLCREATETHREAD            12
#define    ERROR_INVALIDNTHEADER            13
#define    ERROR_ISTHREADID                 14
#define    ERROR_GETPDB                     15
#define    ERROR_THREADLIST                 16
#define    ERROR_LOADLIBRARY                17
#define    ERROR_GETPROCADDRESS             18
#define    ERROR_INVALIDPARAMETER           19
#define    ERROR_PATCH                      20
#define    ERROR_MAX                        20

struct _RDATA;

// User window handler
typedef LRESULT (WINAPI* USERWNDPROC)(struct _RDATA, HWND, UINT, WPARAM, LPARAM);

// System functions loaded dinamically
typedef LONG (WINAPI *SETWINDOWLONG)(HWND, int, LONG);
typedef LRESULT (WINAPI *CALLWINDOWPROC)(WNDPROC, HWND, UINT, WPARAM, LPARAM);
typedef BOOL (WINAPI *POSTMESSAGE)(HWND, UINT, WPARAM, LPARAM);
typedef HMODULE (WINAPI *LOADLIBRARY)(char *);     // ANSI
typedef BOOL (WINAPI *FREELIBRARY)(HMODULE);
typedef HMODULE (WINAPI *GETMODULEHANDLE)(char *); // ANSI

// Data structure filled by GetOffsets()
// (if modified OFFSETS struc in Stub.asm must be modified too !)
typedef struct _OFFSETS {
    // Stub() data
    uintptr_t StubStart;
    uintptr_t StubSize;
    uintptr_t PUserFunc;
    uintptr_t PLdrShutdownThread;
    uintptr_t PNtFreeVirtualMemory;
    uintptr_t PNtTerminateThread;
    uintptr_t PNative;
    uintptr_t PFinished;
    // StubWndProc() data
    uintptr_t StubWndProcStart;
    uintptr_t StubWndProcSize;
    uintptr_t pRDATA;
} OFFSETS, *POFFSETS;

extern void __stdcall GetOffsets(POFFSETS offs);

// Remote data structure
// (if modified RDATA struc in Stub.asm must be modified too !)
typedef struct _RDATA {
    int             Size;                   // Size of structure
    HANDLE          hProcess;               // Process handle
    DWORD           ProcessFlags;           // Process flags
    DWORD           dwTimeout;              // Timeout
    HWND            hWnd;                   // Window handle
    struct _RDATA   *pRDATA;                // Pointer to RDATA structure
    WNDPROC         pfnStubWndProc;         // Address of stub window handler
    USERWNDPROC     pfnUserWndProc;         // Address of user's window procedure handler
    WNDPROC         pfnOldWndProc;          // Address of old window handler
    LRESULT         Result;                 // Result from user's window procedure handler
    SETWINDOWLONG   pfnSetWindowLong;       // Address of SetWindowLong()
    CALLWINDOWPROC  pfnCallWindowProc;      // Address of CallWindowProc()
} RDATA, *PRDATA;

// Data needed by InjectDll()/EjectDll()
typedef struct {
    int             Result;                 // Result from remote thread
    HMODULE         hRemoteDll;             // Handle of remote Dll
    char            szDll[MAX_PATH + 1];    // Name of Dll
    LOADLIBRARY     LoadLibrary;            // LoadLibrary()
    FREELIBRARY     FreeLibrary;            // FreeLibrary()
    GETMODULEHANDLE GetModuleHandle;        // GetModuleHandle()
} RDATADLL, *PRDATADLL;

// Functions declaration
DWORD DLL_IMP_EXP GetProcessInfo(DWORD dwPID);
int DLL_IMP_EXP RemoteExecute(HANDLE hProcess, DWORD ProcessFlags, LPTHREAD_START_ROUTINE Function, PVOID pParams, DWORD Size, DWORD dwTimeout, PDWORD ExitCode);
int DLL_IMP_EXP InjectDllA(HANDLE hProcess, DWORD ProcessFlags, LPCSTR szDllPath, DWORD dwTimeout, HINSTANCE *hRemoteDll);
int DLL_IMP_EXP InjectDllW(HANDLE hProcess, DWORD ProcessFlags, LPCWSTR szDllPath, DWORD dwTimeout, HINSTANCE *hRemoteDll);
int DLL_IMP_EXP EjectDllA(HANDLE hProcess, DWORD ProcessFlags, LPCSTR szDllPath, HINSTANCE hRemoteDll, DWORD dwTimeout);
int DLL_IMP_EXP EjectDllW(HANDLE hProcess, DWORD ProcessFlags, LPCWSTR szDllPath, HINSTANCE hRemoteDll, DWORD dwTimeout);

#ifdef UNICODE
    #define InjectDll  InjectDllW
    #define EjectDll   EjectDllW
#else
    #define InjectDll  InjectDllA
    #define EjectDll   EjectDllA
#endif

// Exported functions type
typedef DWORD (* GETPROCESSINFO)(DWORD);
typedef int (* REMOTEEXECUTE)(HANDLE, DWORD, LPTHREAD_START_ROUTINE, PVOID, DWORD, DWORD, PDWORD);
typedef int (* INJECTDLL)(HANDLE, DWORD, LPCTSTR, DWORD, HINSTANCE *);
typedef int (* EJECTDLL)(HANDLE, DWORD, LPCTSTR, HINSTANCE, DWORD);

#ifdef __cplusplus
  }
#endif

#endif
