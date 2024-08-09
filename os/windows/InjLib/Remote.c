/*************************************************************
 * Library that implements functions used for remote control *
 * and that are missing in some Windows versions.            *
 *                                                           *
 * Emulated functions:                                       *
 * - VirtualAllocEx()                                        *
 * - VirtualFreeEx()                                         *
 * - GetProcessId()                                          *
 * - GetThreadId()                                           *
 * - OpenThread()                                            *
 * - CreateRemoteThread()                                    *
 *                                                           *
 * Bonus functions:                                          *
 * - GetTIB()                                                *
 * - GetTDB()                                                *
 * - GetPDB()                                                *
 * - GetObsfucator()                                         *
 *                                                           *
 * (c) A. Miguel Feijao, 22/4/2005                           *
 *************************************************************/

#define REMOTE_DEFINE_GLOBALS
#include  "Remote.h"
#include  "Struct.h"
#include  "GetProcAddress.h"
#include  "LenDis.h"

#include "log.h"
#include "ezinject_arch.h"

int     OSMajorVersion, OSMinorVersion, OSBuildVersion;
BOOL    OSWin9x, OSWin95, OSWin98, OSWinMe;
BOOL    OSWinNT, OSWinNT3_2003, OSWinVista_7;
DWORD   dwObsfucator;               // Win 9x obfuscator
IMTE    **pMTEModTable;             // Global IMTE table
DWORD   Win16Mutex;                 // Win16Mutex
DWORD   Krn32Mutex;                 // Krn32Mutex

/**********************
 * Find s2 within s1. *
 **********************/
char *MemSearch(char *s1, size_t len1, char *s2, size_t len2)
{
    char *pLastCmp, *p;

    if (len1 == 0 || len2 == 0 || len1 < len2)
        return NULL;

    pLastCmp = &s1[len1 - len2];
    p = s1;

    while (p <= pLastCmp)
    {
        if (memcmp(p, s2, len2) == 0)
            return p;
         else
            p++;
     }
     return NULL;
}


/***********************************************************
 * GetTIB()                                                *
 *                                                         *
 * Return a pointer to the Thread Information Block (TIB). *
 * (return value must be casted depending on OS version)   *
 ***********************************************************/
PTIB GetTIB()
{
    PTIB tib = NULL;
    __asm__ (
        "mov %%fs:0x18, %0\n\t"
    : "=r"(tib)
    );
    return tib;
}


/*********************************************************
 * GetTDB()                                              *
 *                                                       *
 * Return a pointer to the Thread Database (TDB).        *
 * (return value must be casted depending on OS version) *
 *********************************************************/
PTDB GetTDB(DWORD TID)
{
    PTDB pTDB;

    // TDB exists only in the Win9x platform
    if (!OSWin9x)
        return NULL;

    // Pointer to TDB (Thread Database)
    pTDB = (PTDB)(TID ^ dwObsfucator);

    // Check TDB address
    if (IsBadReadPtr(pTDB, sizeof(DWORD)))
        return NULL;

    // Check if object is a thread
    if (OSWin95 && ((PTDB95)pTDB)->Type == WIN95_K32OBJ_THREAD)
        return pTDB;
    else if (((PTDB98)pTDB)->Type == WIN98_K32OBJ_THREAD)
        return pTDB;

    return NULL;
}


/*********************************************************
 * GetPDB()                                              *
 *                                                       *
 * Return a pointer to the Process Database (TDB).       *
 * (return value must be casted depending on OS version) *
 *********************************************************/
PPDB GetPDB(DWORD PID)
{
    PPDB pPDB = NULL;

    // PDB exists only in the Win9x platform
    if (!OSWin9x)
        return NULL;

    // Pointer to PDB (Process Database)
    if (PID == -1) // Local process
    {
        __asm__ (
            "mov %%fs:0x30, %0\n\t"
        : "=r"(pPDB)
        );
    }
    else
        pPDB = (PPDB)(PID ^ dwObsfucator);

    // Check PDB address
    if (IsBadReadPtr(pPDB, sizeof(DWORD)))
        return NULL;

    // Check if object is a process
    if (OSWin95 && ((PPDB95)pPDB)->Type == WIN95_K32OBJ_PROCESS)
        return pPDB;
    else if (((PPDB98)pPDB)->Type == WIN98_K32OBJ_PROCESS)
        return pPDB;

    return NULL;
}


/****************************************
 * GetObsfucator()                      *
 *                                      *
 * Return the Win9x "obfuscator" value. *
 * Obsfucator = PDB xor PID             *
 ****************************************/
DWORD GetObsfucator()
{
    DWORD PID, PDB;
    PID = GetCurrentProcessId();


    __asm__ (
        "mov %%fs:0x30, %0\n\t"
    : "=r"(PDB)
    );
    return PDB ^ PID;
}


////////////////////////// VirtualAllocEx() ///////////////////////////

/**********************
 * VirtualAllocEx9x() *
 **********************/
LPVOID VirtualAllocEx9x(HANDLE hProcess,
                        LPVOID lpAddress,
                        DWORD dwSize,
                        DWORD flAllocationType,
                        DWORD flProtect)
{
    return VirtualAlloc(lpAddress,                      // Starting address of memory block
                        dwSize,                         // Size of memory block
                        flAllocationType | VA_SHARED,   // Allocation type OR Shared memory flag
                        flProtect);                     // Access protection
}


/***********************
 * VirtualAllocExNT3() *
 ***********************/
LPVOID VirtualAllocExNT3(HANDLE hProcess,
                         LPVOID lpAddress,
                         DWORD dwSize,
                         DWORD flAllocationType,
                         DWORD flProtect)
{
    NTSTATUS Status;

    Status = NtAllocateVirtualMemory(hProcess,          // Process handle
                                     &lpAddress,        // Memory address
                                     0,                 // Zero bits
                                     &dwSize,           // Region size
                                     flAllocationType,  // Allocation type
                                     flProtect);        // Protection attributes

    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return NULL;
    }

    return lpAddress;
}


/*************************************************************
 * _VirtualAllocEx()                                         *
 *                                                           *
 * Reserves or commits a region of memory within the virtual *
 * address space of a specified process.                     *
 *                                                           *
 * Implemented: WinNT4.0 or later                            *
 * Emulated   : Win9x, WinNT3.51-                            *
 *                                                           *
 *************************************************************/
LPVOID _VirtualAllocEx(HANDLE hProcess,        // Process within which to allocate memory
                       LPVOID lpAddress,       // Desired starting address of allocation
                       DWORD dwSize,           // Size, in bytes, of region to allocate
                       DWORD flAllocationType, // Type of allocation
                       DWORD flProtect)        // Type of access protection
{
    // Win 9x, Me
    if (OSWin9x)
        return VirtualAllocEx9x(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
    // Win NT 3.51 or less
    else if (OSWinNT && OSMajorVersion < 4)
        return VirtualAllocExNT3(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
    // Win NT 4.0 or later
    else if (OSWinNT && OSMajorVersion >= 4)
        return K32_VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
    else
        return NULL;
}

/////////////////////////// VirtualFreeEx() ///////////////////////////

/*********************
 * VirtualFreeEx9x() *
 *********************/
BOOL VirtualFreeEx9x(HANDLE hProcess,
                     LPVOID lpAddress,
                     DWORD dwSize,
                     DWORD dwFreeType)
{
    return VirtualFree(lpAddress,           // Address of memory block
                       dwSize,              // Size of memory block
                       dwFreeType);         // Type of free operation
}


/**********************
 * VirtualFreeExNT3() *
 **********************/
BOOL VirtualFreeExNT3(HANDLE hProcess,
                      LPVOID lpAddress,
                      DWORD dwSize,
                      DWORD dwFreeType)
{
    NTSTATUS Status;

    // Param 'dwSize' must be zero for MEM_RELEASE
    if ((dwFreeType & MEM_RELEASE) && (dwSize != 0))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    Status = NtFreeVirtualMemory(hProcess,      // Process handle
                                 &lpAddress,    // Base address
                                 &dwSize,       // Region size
                                 dwFreeType);   // Free type

    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/****************************************************
 * _VirtualFreeEx()                                 *
 *                                                  *
 * Releases/decommits a region of memory within the *
 * virtual address space of a specified process.    *
 *                                                  *
 * Implemented: WinNT4.0 or later                   *
 * Emulated   : Win9x, WinNT3.51-                   *
 *                                                  *
 ****************************************************/
BOOL _VirtualFreeEx(HANDLE hProcess,  // Process within which to free memory
                    LPVOID lpAddress, // Starting address of memory region to free
                    DWORD dwSize,     // Size, in bytes, of memory region to free
                    DWORD dwFreeType) // Type of free operation
{
    // Win 9x, Me
    if (OSWin9x)
        return VirtualFreeEx9x(hProcess, lpAddress, dwSize, dwFreeType);
    // Win NT 3.51 or less
    else if (OSWinNT && OSMajorVersion < 4)
        return VirtualFreeExNT3(hProcess, lpAddress, dwSize, dwFreeType);
    // Win NT 4 or later
    else if (OSWinNT && OSMajorVersion >= 4)
        return K32_VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType);
    else
        return FALSE;
}


///////////////////////////// OpenThread() ////////////////////////////

/********************************
 * OpenThread9x()               *
 *                              *
 * InternalOpenThread() method. *
 ********************************/
HANDLE OpenThread9x(DWORD dwDesiredAccess,
                    BOOL  bInheritHandle,
                    DWORD dwThreadId)
{
#ifdef _WIN64
    return NULL;
#else
    HANDLE  hThread;
    PTDB    pTDB;

    SetLastError(ERROR_INVALID_PARAMETER);

    // Check if TID is valid
    if (!IsThreadId(dwThreadId))
        return NULL;

    // Thread Database pointer
    if (!(pTDB = GetTDB(dwThreadId)))
        return NULL;

    // InternalOpenThread()
    __asm__(
        "mov %[tdb], %%eax\n\t"
        "push %[tid]\n\t"
        "push %[inherit]\n\t"
        "push %[access]\n\t"
        "call %[openThread]\n\t"
        "mov %%eax, %[hThread]"
    : [hThread] "=r"(hThread)
    : [tdb] "r"(pTDB),
      [tid] "r"(dwThreadId),
      [inherit] "r"(bInheritHandle),
      [access] "r"(InternalOpenThread),
      [openThread] "r"(InternalOpenThread)
    );
    return hThread;
#endif
}


/******************
 * OpenThreadNT() *
 ******************/
HANDLE OpenThreadNT(DWORD dwDesiredAccess,
                    BOOL  bInheritHandle,
                    DWORD dwThreadId)
{
    OBJECT_ATTRIBUTES   ObjectAttributes;
    CLIENT_ID           ClientId;
    HANDLE              hThread;
    NTSTATUS            Status;

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

    if (bInheritHandle)
        ObjectAttributes.Attributes = OBJ_INHERIT;

    ClientId.UniqueProcess = NULL;
    ClientId.UniqueThread = (HANDLE)dwThreadId;

    Status = NtOpenThread(&hThread,             // Thread handle
                          dwDesiredAccess,      // Access to thread object
                          &ObjectAttributes,    // Attributes of the thread to open
                          &ClientId);           // Ptr to CLIENT_ID struct

    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return NULL;
    }

    return hThread;
}


/***************************************
 * _OpenThread()                       *
 *                                     *
 * Opens an existing thread object.    *
 *                                     *
 * Implemented: Win2K, Win2003, XP, Me *
 * Emulated   : Win9x, WinNT           *
 *                                     *
 ***************************************/
HANDLE _OpenThread(DWORD dwDesiredAccess,   // Access to the thread object
                   BOOL  bInheritHandle,    // Inherit handle
                   DWORD dwThreadId)        // ID of thread to be opened
{
    // Win 95, 98
    if (OSWin95 || OSWin98)
        return OpenThread9x(dwDesiredAccess, bInheritHandle, dwThreadId);
    // Win NT 4.0 or less
    else if (OSWinNT && OSMajorVersion <= 4)
        return OpenThreadNT(dwDesiredAccess, bInheritHandle, dwThreadId);
    // Win Me, Win NT 2000 or later
    else if (OSWinMe || (OSWinNT && OSMajorVersion >= 5))
        return K32_OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);
    else
        return NULL;
}


///////////////////////////// GetProcessId() ////////////////////////////

/********************
 * GetProcessId9x() *
 ********************/
DWORD GetProcessId9x(HANDLE hProcess)
{
    PPDB            pPDB, pObject;
    PHANDLE_TABLE   pHandleTable;
    int             index, NumberOfHandleTableEntries;
    BOOL            bIsProcessObject;

    SetLastError(ERROR_INVALID_PARAMETER);

    // hProcess == NULL
    if (!hProcess)
        return 0;

    // Cannot use a pseudo handle !
    if (hProcess == GetCurrentProcess())
        return GetCurrentProcessId(); // PID = pPDBLocal ^ dwObsfucator

    // Current Process Database pointer
    if (!(pPDB = GetPDB(-1)))
        return 0;

    // Get handle table pointer and index
    if (OSWin95)
    {
        index = (DWORD)hProcess;
        pHandleTable = ((PPDB95)pPDB)->pHandleTable;
    }
    else
    {
        index = (DWORD)hProcess / 4;
        pHandleTable = ((PPDB98)pPDB)->pHandleTable;
    }
    NumberOfHandleTableEntries = pHandleTable->cEntries;

    // Index outside table limits ?
    if ((index <= 0) || (index > NumberOfHandleTableEntries))
        return 0;

    // Pointer to process database
    if (!(pObject = pHandleTable->array[index].pObject))
        return 0;

    // Check pointer
    if (IsBadReadPtr(pObject, sizeof(DWORD)))
        return 0;

    // Check if object is a process
    if (OSWin95)
       bIsProcessObject = ((PPDB95)pObject)->Type == WIN95_K32OBJ_PROCESS;
    else
       bIsProcessObject = ((PPDB98)pObject)->Type == WIN98_K32OBJ_PROCESS;

    if (!bIsProcessObject)
        return 0;

    // Return PID
    return (DWORD)pObject ^ dwObsfucator;
}


/********************
 * GetProcessIdNT() *
 ********************/
DWORD WINAPI GetProcessIdNT(HANDLE hProcess)
{
    NTSTATUS                  Status;
    PROCESS_BASIC_INFORMATION pbi;
    HANDLE                    hDupHandle;
    HANDLE                    hCurrentProcess;

    hCurrentProcess = GetCurrentProcess();

    // Use DuplicateHandle() to get PROCESS_QUERY_INFORMATION access right
    if (!DuplicateHandle(hCurrentProcess,
                         hProcess,
                         hCurrentProcess,
                         &hDupHandle,
                         PROCESS_QUERY_INFORMATION,
                         FALSE,
                         0))
    {
        SetLastError(ERROR_ACCESS_DENIED);
        return 0;
    }

    Status = NtQueryInformationProcess(hDupHandle,
                                       ProcessBasicInformation,
                                       &pbi,
                                       sizeof(pbi),
                                       NULL);

    CloseHandle(hDupHandle);

    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return 0;
    }

    // Return PID
    return (DWORD)pbi.UniqueProcessId;
}


/**************************************************************
 * _GetProcessId()                                            *
 *                                                            *
 * Retrieves the process identifier of the specified process. *
 *                                                            *
 * Implemented: Win2003, XP-SP1                               *
 * Emulated   : Win9x, WinNT                                  *
 *                                                            *
 **************************************************************/
DWORD _GetProcessId(HANDLE hProcess)    // Handle to Process
{
    // Win 9x, Me
    if (OSWin9x)
        return GetProcessId9x(hProcess);
    // Win XP or less
    else if (OSWinNT && (OSMajorVersion <= 4 || (OSMajorVersion == 5 && OSMinorVersion <= 1)))
        return GetProcessIdNT(hProcess);
    // Win 2003
    else if ((OSWinNT && OSMajorVersion == 5 && OSMajorVersion >= 2) || (OSWinNT && OSMajorVersion == 6))
        return K32_GetProcessId(hProcess);
    else
        return 0;
}

///////////////////////////// GetThreadId() ////////////////////////////

/*******************
 * GetThreadId9x() *
 *******************/
DWORD GetThreadId9x(HANDLE hThread)
{
    PPDB            pPDB, pObject;
    PHANDLE_TABLE   pHandleTable;
    int             index, NumberOfHandleTableEntries;
    BOOL            bIsThreadObject;

    SetLastError(ERROR_INVALID_PARAMETER);

    // hThread == NULL
    if (!hThread)
        return 0;

    // Cannot use a pseudo handle !
    if (hThread == GetCurrentThread())
        return GetCurrentThreadId();  // TID = pTDBLocal ^ dwObsfucator

    // Current PDB
    if (!(pPDB = GetPDB(-1)))
        return 0;

    // Get handle table pointer and index
    if (OSWin95)
    {
        index = (DWORD)hThread;
        pHandleTable = ((PPDB95)pPDB)->pHandleTable;
    }
    else
    {
        index = (DWORD)hThread / 4;
        pHandleTable = ((PPDB98)pPDB)->pHandleTable;
    }
    NumberOfHandleTableEntries = pHandleTable->cEntries;

    // Index outside table limits ?
    if ((index <= 0) || (index > NumberOfHandleTableEntries))
        return 0;

    // Pointer to thread database
    if (!(pObject = pHandleTable->array[index].pObject))
        return 0;

    // Check pointer
    if (IsBadReadPtr(pObject, sizeof(DWORD)))
        return 0;

    // Check if object is a thread
    if (OSWin95)
       bIsThreadObject = ((PTDB95)pObject)->Type == WIN95_K32OBJ_THREAD;
    else
       bIsThreadObject = ((PTDB98)pObject)->Type == WIN98_K32OBJ_THREAD;

    if (!bIsThreadObject)
        return 0;

    // Return TID
    return (DWORD)pObject ^ dwObsfucator;
}


/*******************
 * GetThreadIdNT() *
 *******************/
DWORD WINAPI GetThreadIdNT(HANDLE hThread)
{
    NTSTATUS                 Status;
    THREAD_BASIC_INFORMATION tbi;
    HANDLE                   hDupHandle;
    HANDLE                   hCurrentProcess;

    hCurrentProcess = GetCurrentProcess();

    // Use DuplicateHandle() to get THREAD_QUERY_INFORMATION access right
    if (!DuplicateHandle(hCurrentProcess,
                         hThread,
                         hCurrentProcess,
                         &hDupHandle,
                         THREAD_QUERY_INFORMATION,
                         FALSE,
                         0))
    {
        SetLastError(ERROR_ACCESS_DENIED);
        return 0;
    }

    Status = NtQueryInformationThread(hDupHandle,
                                      ThreadBasicInformation,
                                      &tbi,
                                      sizeof(tbi),
                                      NULL);

    CloseHandle(hDupHandle);

    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return 0;
    }

    // Return TID
    return (DWORD)tbi.ClientId.UniqueThread;
}


/************************************************************
 * _GetThreadId()                                           *
 *                                                          *
 * Retrieves the thread identifier of the specified thread. *
 *                                                          *
 * Implemented: Win2003                                     *
 * Emulated   : Win9x, WinNT                                *
 *                                                          *
 ************************************************************/
DWORD _GetThreadId(HANDLE hThread)    // Handle to Thread
{
    // Win 9x, Me
    if (OSWin9x)
        return GetThreadId9x(hThread);
    // Win XP or less
    else if (OSWinNT && (OSMajorVersion <= 4 || (OSMajorVersion == 5 && OSMinorVersion <= 1)))
        return GetThreadIdNT(hThread);
    // Win 2003
    else if ((OSWinNT && OSMajorVersion == 5 && OSMajorVersion >= 2) || (OSWinNT && OSMajorVersion == 6))
        return K32_GetThreadId(hThread);
    else
        return 0;
}

///////////////////////////// CreateRemoteThread() ////////////////////////////

/**************************
 * CreateRemoteThread9x() *
 **************************/
HANDLE CreateRemoteThread9x(HANDLE hProcess,
                            LPSECURITY_ATTRIBUTES  lpThreadAttributes,
                            DWORD                  dwStackSize,
                            LPTHREAD_START_ROUTINE lpStartAddress,
                            LPVOID                 lpParameter,
                            DWORD                  dwCreationFlags,
                            LPDWORD                lpThreadId)
{
    #define INVALID_FLAGS (fTerminated | fTerminating | fNearlyTerminating) // 0x30800000

    PPDB    pPDB, pPDBLocal;
    PTDB    pTDB;
    DWORD   dwThreadId, dwProcessId;
    HANDLE  hThread;
    BOOL    bInheritHandle = FALSE;
    DWORD   fLocal;
    DWORD   fFlags = 8; // Initial flag for InternalCreateRemoteThread()
    DWORD   StackSize;

    SetLastError(ERROR_INVALID_PARAMETER);

    if (lpThreadAttributes != NULL)
    {
        if (lpThreadAttributes->nLength != sizeof(SECURITY_ATTRIBUTES))
            return NULL;

        bInheritHandle = lpThreadAttributes->bInheritHandle;
    }

    if (!lpStartAddress)
        return NULL;

    // Get PID
    if (!(dwProcessId = _GetProcessId(hProcess)))
        return NULL;

    //Get PDB
    if (!(pPDB = GetPDB(dwProcessId)))
        return NULL;

    // Check process flags
    if (((PPDB95)pPDB)->Flags & INVALID_FLAGS)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    // Get local PDB
    if (!(pPDBLocal = GetPDB(-1)))
        return NULL;

    // Is the process local or remote ?
    fLocal = pPDB == pPDBLocal;

    // Remote process
    // (negate stack size)
    if (!fLocal)
    {
        if (dwStackSize == 0)
            StackSize = -(int)0x3000;   // Default stack size
        else
            StackSize = -(int)dwStackSize;
    }
    // Current process
    else
        StackSize = dwStackSize;

    // Always create thread suspended
    fFlags |= 0x40;

    // If process not initialized
    // suppress DLL_THREAD_ATTACH notification
    // (c) R. Picha
    if (dwCreationFlags & CREATE_SILENT)
        fFlags |= 0x10;

    // Set correct system level
    EnterSysLevel(Win16Mutex);
    if (Krn32Mutex)
        EnterSysLevel(Krn32Mutex);

    // This function creates a new THREAD object and returns a pointer to it
    // (run thread)
    pTDB = InternalCreateRemoteThread(pPDB,             // PDB
                                      StackSize,        // Stack size
                                      lpStartAddress,   // Thread address
                                      lpParameter,      // Parameter passed to thread
                                      fFlags);          // Flags
    // Leave system level
    if (Krn32Mutex)
        LeaveSysLevel(Krn32Mutex);
    LeaveSysLevel(Win16Mutex);

    dwThreadId = (DWORD)pTDB ^ dwObsfucator;

    if (lpThreadId != NULL)
        *lpThreadId = dwThreadId;

    // Get thread handle
    hThread = OpenThread9x(THREAD_ALL_ACCESS, bInheritHandle, dwThreadId);

    // If thread created not suspended let it run
    if (!(dwCreationFlags & CREATE_SUSPENDED))
        ResumeThread(hThread);

    return hThread;
}


/**************************************************************
 * _CreateRemoteThread()                                      *
 *                                                            *
 * Creates a thread that runs in the virtual address space of *
 * another process.                                           *
 *                                                            *
 * Implemented: Win NT or later                               *
 * Emulated   : Win9x                                         *
 *                                                            *
 **************************************************************/
HANDLE _CreateRemoteThread(HANDLE hProcess,                             // Handle to the process in which the thread is to be created
                           LPSECURITY_ATTRIBUTES  lpThreadAttributes,   // Security descriptor for the new thread
                           DWORD                  dwStackSize,          // Initial size of the stack, in bytes
                           LPTHREAD_START_ROUTINE lpStartAddress,       // Thread address
                           LPVOID                 lpParameter,          // Pointer to a variable to be passed to the thread function
                           DWORD                  dwCreationFlags,      // Flags that control the creation of the thread
                           LPDWORD                lpThreadId)           // Pointer to a variable that receives the thread identifier
{
	NTSTATUS               Status;
	HANDLE                 hThread;
	NTCREATETHREADEXBUFFER ntBuffer;
	DWORD                  dw0, dw1;

    // Win 9x, Me
    if (OSWin9x)
        return CreateRemoteThread9x(hProcess,
                                    lpThreadAttributes,
                                    dwStackSize,
                                    lpStartAddress,
                                    lpParameter,
                                    dwCreationFlags,
                                    lpThreadId);
    // Win NT 3.1 to 2003
    else if (OSWinNT3_2003)
        return K32_CreateRemoteThread(hProcess,
                                      lpThreadAttributes,
                                      dwStackSize,
                                      lpStartAddress,
                                      lpParameter,
                                      dwCreationFlags,
                                      lpThreadId);
    // Win Vista or later
    else if (OSWinVista_7)
	{
		// Setup and initialize the buffer
        memset(&ntBuffer, 0, sizeof(NTCREATETHREADEXBUFFER));
        dw0 = 0;
        dw1 = 0;

        ntBuffer.Size = sizeof(NTCREATETHREADEXBUFFER);
        ntBuffer.Unknown1 = 0x10003;
        ntBuffer.Unknown2 = 0x8;
        ntBuffer.Unknown3 = &dw1;
        ntBuffer.Unknown4 = 0;
        ntBuffer.Unknown5 = 0x10004;
        ntBuffer.Unknown6 = 4;
        ntBuffer.Unknown7 = &dw0;
        ntBuffer.Unknown8 = 0;

        Status = NtCreateThreadEx(&hThread,                                             // ThreadHandle (OUT)
                                  (STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL),          // DesiredAccess
                                  NULL,                                                 // ObjectAttributes
                                  hProcess,                                             // ProcessHandle
                                  lpStartAddress,                                       // StartRoutine
                                  lpParameter,                                          // Argument
                                  (dwCreationFlags == CREATE_SUSPENDED) ? TRUE : FALSE, // CreationFlags
                                  0L,                                                   // StackZeroBits
                                  0L,                                                   // StackCommit
                                  0L,                                                   // StackReserve
                                  &ntBuffer);                                           // AttributeList (OUT)

        if (!NT_SUCCESS(Status))
		{
            SetLastError(RtlNtStatusToDosError(Status));
            return NULL;
		}

		if (lpThreadId)
			*lpThreadId = K32_GetThreadId(hThread);

		return hThread;
	}

    else
        return NULL;
}


/********************************************************************
 * Return a TID (thread id) for the specified process. (Win9x only) *
 ********************************************************************/
DWORD GetProcessThread9x(DWORD PID)
{
    PPDB        pPDB;
    DWORD       *pThreadHead;
    PTHREADLIST pThreadNode;
    DWORD       TID = 0;
    HANDLE      hThread;
    CONTEXT     c = {CONTEXT_CONTROL | CONTEXT_INTEGER};

    // Get thread list (from PDB)
    if (!(pPDB = GetPDB(PID)))
        return 0;
    if (!(pThreadHead = (DWORD *)((PPDB98)pPDB)->ThreadList))
        return 0;
    if (!(pThreadNode = (THREADLIST *)*pThreadHead))
        return 0;

    do
    {
        TID = pThreadNode->pTDB ^ dwObsfucator;

        if (!(hThread = OpenThread9x(THREAD_ALL_ACCESS, FALSE, TID)))
            continue;

        if (!GetThreadContext(hThread, &c))
        {
            CloseHandle(hThread);
            continue;
        }

        // Threads below this address make the system crash (?!?)
        if (REG(c, REG_PC) > 0x400000)
        {
            CloseHandle(hThread);
            return TID;
        }

        CloseHandle(hThread);
    } while (pThreadNode = (THREADLIST *)pThreadNode->pNext);

    return 0;
}

/*******************************************************
 * Return a TID (thread id) for the specified process. *
 * (use the Toolhelp functions)                        *
 *******************************************************/
DWORD GetProcessThreadToolhelp(DWORD dwPID)
{
  HANDLE        hSnapshot = INVALID_HANDLE_VALUE;
  THREADENTRY32 te;
  HANDLE        hThread;
  DWORD         TID = 0;
  CONTEXT       c = {CONTEXT_CONTROL | CONTEXT_INTEGER};

  hSnapshot = K32_CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwPID);
  if (hSnapshot == INVALID_HANDLE_VALUE)
      return 0;

  te.dwSize = sizeof(THREADENTRY32);

  if (!K32_Thread32First(hSnapshot, &te))
  {
      CloseHandle(hSnapshot);
      return 0;
  }

  do
  {
      if (te.th32OwnerProcessID == dwPID)
      {
          TID = te.th32ThreadID;

          if (!(hThread = _OpenThread(THREAD_ALL_ACCESS, FALSE, TID)))
              continue;

          if (OSWin9x)
          {
              if (!GetThreadContext(hThread, &c))
              {
                  CloseHandle(hThread);
                  continue;
              }

              // Threads below this address make the system crash (?!?)
             if (REG(c, REG_PC) > 0x400000)
             {
                 CloseHandle(hThread);
                 CloseHandle(hSnapshot);
                 return TID;
             }
          }
          else
          {
              CloseHandle(hThread);
              CloseHandle(hSnapshot);
              return TID;
          }
          CloseHandle(hThread);
      }
  } while (K32_Thread32Next(hSnapshot, &te));

  CloseHandle(hSnapshot);
  return 0;
}


/*******************************************************
 * Return a TID (thread id) for the specified process. *
 * (use the NtQuerySystemInformation() function)       *
 *******************************************************/
DWORD GetProcessThreadNtQuerySystemInformation(DWORD dwPID)
{
    PSYSTEM_PROCESS_INFORMATION pInfo;
    PSYSTEM_THREAD_INFORMATION  pThreads;
    ULONG   BufferLen = 0x4000;
    LPVOID  pBuffer = NULL;
    LONG    Status;
    DWORD   dwThreadId;
    ULONG   ThreadCount;
    ULONG   i;
    HANDLE  hThread;
    CONTEXT c = {CONTEXT_CONTROL | CONTEXT_INTEGER};

    // Find needed buffer length
    do
    {
        if (!(pBuffer = malloc(BufferLen)))
            return 0;

        Status = NtQuerySystemInformation(SystemProcessesAndThreadsInformation,
                                          pBuffer, BufferLen, NULL);

        if (Status == STATUS_INFO_LENGTH_MISMATCH)
        {
            free(pBuffer);
            BufferLen *= 2;
        }
        else if (!NT_SUCCESS(Status))
        {
            free(pBuffer);
            return 0;
        }
    }
    while (Status == STATUS_INFO_LENGTH_MISMATCH);

    pInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
    for (;;)
    {
        if ((DWORD)pInfo->UniqueProcessId == dwPID)
        {
            ThreadCount = pInfo->NumberOfThreads;

            if (OSMajorVersion < 5)
                pThreads = ((PSYSTEM_PROCESS_INFORMATION_NT4)pInfo)->Threads;
            else
                pThreads = pInfo->Threads;

            for (i = 0; i < ThreadCount; i++)
            {
                dwThreadId = (DWORD)pThreads[i].ClientId.UniqueThread;

                if (!(hThread = _OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId)))
                    continue;

                CloseHandle(hThread);
                free(pBuffer);
                return dwThreadId;
            }
        }

        if (pInfo->NextEntryOffset == 0)
            break;

        // Find the address of the next process structure
        pInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pInfo) + pInfo->NextEntryOffset);
    }

    free(pBuffer);

    return 0;
}

/*******************************************************
 * Return a TID (thread id) for the specified process. *
 *******************************************************/
DWORD _GetProcessThread(DWORD dwPID)
{
    if (OSWin9x)
        return GetProcessThread9x(dwPID);
    else if (OSWinNT && OSMajorVersion < 5)
        return GetProcessThreadNtQuerySystemInformation(dwPID);
    else if (OSWinNT && OSMajorVersion >= 5)
        return GetProcessThreadToolhelp(dwPID);
    else
        return 0;
}


/////////////////////////////////////// Initialization ///////////////////////////////////////////

/**************************************************************
 * Initialize required data depending on the Windows version. *
 **************************************************************/
BOOL Initialization()
{
    OSVERSIONINFO   osvi;
    HMODULE         hNTDLL = NULL, hKernel32 = NULL;
    PVOID           pDebugActiveProcess, pOpenProcess, pGDIReallyCares;
    int             DebugActiveProcessLength, OpenProcessLength, GDIReallyCaresLength;
    DWORD           OpenProcessOrdinal, DebugActiveProcessOrdinal;
    PBYTE           p;
    BOOL            Result = FALSE;
    static BOOL     bInitializing = FALSE;

    HINSTANCE               pBase;
    PIMAGE_DOS_HEADER       pDOSHeader;
    PIMAGE_NT_HEADERS       pNTHeader;
    PIMAGE_SECTION_HEADER   pImageSectionArray;
    int                     nNumberOfSections;
    DWORD                   SectionStart;
    DWORD                   K32Table;
    int                     nLocks;
    DWORD                   *pMutex;
    int                     len, Res, Displacement;
    int                     i, SearchLen;
    DWORD                   Addr;

    // Not reentrant
    if (bInitializing)
        return FALSE;
    bInitializing = TRUE;

    do {
        do {
            // Get Windows version
            osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
            if (!GetVersionEx(&osvi))
                break;

            // Save version data in global variables
            OSMajorVersion = osvi.dwMajorVersion;
            OSMinorVersion = osvi.dwMinorVersion;
            OSBuildVersion = LOWORD(osvi.dwBuildNumber);
            OSWin9x = osvi.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS;
            OSWin95 = (OSWin9x && OSMajorVersion == 4 && OSMinorVersion < 3)  ? TRUE : FALSE;   // Win95 OSR2.0 -
            OSWin98 = (OSWin9x && OSMajorVersion == 4 &&
                      (OSMinorVersion >= 3 && OSMinorVersion <= 10)) ? TRUE : FALSE;            // Win98 or Win95 OSR2.1+
            OSWinMe = (OSWin9x && OSMajorVersion == 4 && OSMinorVersion >= 90) ? TRUE : FALSE;  // Win Me
            OSWinNT = osvi.dwPlatformId == VER_PLATFORM_WIN32_NT;
			OSWinNT3_2003 = (OSWinNT && OSMajorVersion >= 3 && OSMajorVersion <= 5) ? TRUE : FALSE; // Win 3.1 to 2003
			OSWinVista_7 = (OSWinNT && OSMajorVersion == 6) ? TRUE : FALSE; // Win Vista to 7 (8 ?)
            OSWinNT3 = (OSWinNT && OSMajorVersion == 3);

            DBG("OS Major: %u, Minor: %u", OSMajorVersion, OSMinorVersion);

            /***** Win 9x *****/
            if (OSWin9x)
            {
                // Win9x "Obfuscator"
                dwObsfucator = GetObsfucator();

                if (!(hKernel32 = LoadLibrary(TEXT("Kernel32.dll"))))
                    break;

                // Get Kernel32 IsThreadId() address
                // (cannot use GetProcAddress() because it doesn't allow to retreive Kernel32 functions addresses by ordinal in Win9x)
                if (!(IsThreadId = (ISTHREADID)_GetProcAddress(hKernel32, ISTHREADID_ORDINAL)))
                    break;

                // Get GetpWin16Lock(), EnterSysLevel() and LeaveSysLevel() functions addresses
                if (!(GetpWin16Lock = (GETPWIN16LOCK)_GetProcAddress(hKernel32, GETPWIN16LOCK_ORDINAL)))
                    break;
                if (!(EnterSysLevel = (ENTERSYSLEVEL)_GetProcAddress(hKernel32, ENTERSYSLEVEL_ORDINAL)))
                    break;
                if (!(LeaveSysLevel = (LEAVESYSLEVEL)_GetProcAddress(hKernel32, LEAVESYSLEVEL_ORDINAL)))
                    break;

                // Get Win16Mutex
                Win16Mutex = 0;
                GetpWin16Lock(&Win16Mutex);
                if (Win16Mutex == 0)
                    break;

                /*** Get Krn32Mutex from Kernel32.dll ***/
                Krn32Mutex = 0;
                // Library base address
                pBase = hKernel32;

                // Verify DOS header
                pDOSHeader = (PIMAGE_DOS_HEADER)pBase;
                if (pDOSHeader->e_magic == IMAGE_DOS_SIGNATURE) // "MZ"
                {
                    // NT Header
                    pNTHeader = (PIMAGE_NT_HEADERS)((LONG)pDOSHeader + pDOSHeader->e_lfanew);
                    if (pNTHeader->Signature == LOWORD(IMAGE_NT_SIGNATURE)) // "PE"
                    {
                        pImageSectionArray = IMAGE_FIRST_SECTION(pNTHeader);
                        nNumberOfSections = pNTHeader->FileHeader.NumberOfSections;

                        // Search all image sections
                        for (i=0; i < nNumberOfSections; i++)
                        {
                            SectionStart = (DWORD)pBase + pImageSectionArray[i].VirtualAddress;

                            if (!IsBadReadPtr((void *)SectionStart, 4) && _strnicmp((char *)SectionStart, "KEXP", 4) == 0)
                            {
                                K32Table = *(DWORD *)(SectionStart + 8);
                                if (OSWin95)
                                    Krn32Mutex = *(DWORD *)(K32Table + 0x28); // Win95 OSR 2.0 -
                                else
                                    Krn32Mutex = *(DWORD *)(K32Table + 0x30); // Win95 OSR 2.1 +
                                break;
                            }
                        }
                    }
                }

                // Get OpenProcess() address and length
                OpenProcessOrdinal = NameToOrdinal(hKernel32, "OpenProcess"); // Win95 and Win98 have different ordinal numbers !
                pOpenProcess = (FARPROC)_GetProcAddress(hKernel32, OpenProcessOrdinal);
                OpenProcessLength = GetProcLength(hKernel32, OpenProcessOrdinal);

                // If running under a debugger get the real address
                if (*(PBYTE)pOpenProcess == 0x68)
				{
                    pOpenProcess = (PVOID)*(DWORD *)((PBYTE)pOpenProcess + 1);
					OpenProcessLength = 0x1000;
				}

                // Search for MOV ECX,0 (B9,00,00,00,00) inside OpenProcess() function
                p = MemSearch(pOpenProcess, OpenProcessLength, "\xB9\x00\x00\x00\x00", 5);
                if (!p)
                    break;

                // Address of InternalOpenThread()
                InternalOpenThread = (INTERNALOPENTHREAD)p;

                // Get DebugActiveProcess() address and length
                DebugActiveProcessOrdinal = NameToOrdinal(hKernel32, "DebugActiveProcess"); // Win95 and Win98 have different ordinal numbers !
                pDebugActiveProcess = (FARPROC)_GetProcAddress(hKernel32, DebugActiveProcessOrdinal);
                DebugActiveProcessLength = GetProcLength(hKernel32, DebugActiveProcessOrdinal);

                // If running under a debugger get the real address
                if (*(PBYTE)pDebugActiveProcess == 0x68)
				{
                    pDebugActiveProcess = (PVOID)*(DWORD *)((PBYTE)pDebugActiveProcess + 1);
					DebugActiveProcessLength = 0x1000;
				}

                // Search for PUSH FFFFF000 (68,00,F0,FF,FF) inside DebugActiveProcess() function
                p = MemSearch(pDebugActiveProcess, DebugActiveProcessLength, "\x68\x00\xF0\xFF\xFF", 5);
                if (!p || p[6] != 0xE8) // CALL InternalCreateRemoteThread (E8,xx,xx,xx,xx)
                    break;
                p += 7; // Point to CALL InternalCreateRemoteThread
                // Address of InternalCreateRemoteThread() inside DebugActiveProcess()
                InternalCreateRemoteThread = (INTERNALCREATEREMOTETHREAD)(p + *(DWORD *)p + 4);

                /*** Search DebugActiveProcess() for EnterSysLevel() calls ***/
                SearchLen = p - (PBYTE)pDebugActiveProcess;
                p = pDebugActiveProcess;
                nLocks = 0;

                while (SearchLen > 0)
                {
                    // Alternative method to find Krn32Mutex
                    if (*p == 0xA1)     // MOV EAX, [xxxxxxxx]
                    {
                        pMutex = (DWORD *)*(DWORD *)(p + 1);
                        if (*pMutex != Win16Mutex && Krn32Mutex == 0)
                            Krn32Mutex = *pMutex;
                    }

                    // Check how many times EnterSysLevel() is called
                    if (*p == 0xE8)     // CALL xxxxxxxx
                    {
                        Addr = (DWORD)p + (DWORD)*(DWORD *)(p + 1) + 5;
                        if (Addr == (DWORD)EnterSysLevel)
                            nLocks++;
                    }

                    len = LengthDisassembler(p, &Res, &Displacement);
                    p += len;
                    SearchLen -= len;
                }

                // Krn32Mutex not found !
                if (nLocks >= 2 && Krn32Mutex == 0)
                    break;

                // Only EnterSysLevel(Win16Mutex) called
                if (nLocks <= 1)
                    Krn32Mutex = 0;

                // Get GDIReallyCares() address and length
                pGDIReallyCares = (FARPROC)_GetProcAddress(hKernel32, GDIREALLYCARES_ORDINAL);
                GDIReallyCaresLength = GetProcLength(hKernel32, GDIREALLYCARES_ORDINAL);

                // If running under a debugger get the real address
                if (*(PBYTE)pGDIReallyCares == 0x68)
				{
                    pGDIReallyCares = (PVOID)*(DWORD *)((PBYTE)pGDIReallyCares + 1);
					GDIReallyCaresLength = 0x1000;
				}

                // Search for MOV ECX,[addr] (8B,0D,...) inside GDIReallyCares() function
                p = MemSearch(pGDIReallyCares, GDIReallyCaresLength, "\x8B\x0D", 2);
                if (!p)
                    break;
                p += 2;
                // Address of pMTEModTable
                pMTEModTable = (IMTE **)*(DWORD *)*(DWORD *)p;

                // Win Me
                if (OSWinMe)
                {
                    if (!(K32_OpenThread = (OPENTHREAD)GetProcAddress(hKernel32, "OpenThread")))
                        break;
                }
            }//Win9x

            /***** Win NT *****/
            if (OSWinNT)
            {
                if (!(hKernel32 = LoadLibrary(TEXT("Kernel32.dll"))))
                    break;

                if (!(hNTDLL = LoadLibrary(TEXT("NTDLL.DLL"))))
                    break;

                // Win NT all versions
                if (!(K32_CreateRemoteThread = (CREATEREMOTETHREAD)GetProcAddress(hKernel32, "CreateRemoteThread")))
                    break;
                if (!(RtlCreateUserThread = (RTLCREATEUSERTHREAD)GetProcAddress(hNTDLL, "RtlCreateUserThread")))
                    break;
                // Windows NT 3 doesn't have this, unsure about 4
                if(OSWinNT && !OSWinNT3){
                    if (!(NtQueueApcThread = (NTQUEUEAPCTHREAD)GetProcAddress(hNTDLL, "NtQueueApcThread")))
                        break;
                }
                if (!(LdrShutdownThread = (LDRSHUTDOWNTHREAD)GetProcAddress(hNTDLL, "LdrShutdownThread")))
                    break;
                if (!(NtTerminateThread = (NTTERMINATETHREAD)GetProcAddress(hNTDLL, "NtTerminateThread")))
                    break;
                if (!(NtAllocateVirtualMemory = (NTALLOCATEVIRTUALMEMORY)GetProcAddress(hNTDLL, "NtAllocateVirtualMemory")))
                    break;
                if (!(NtFreeVirtualMemory = (NTFREEVIRTUALMEMORY)GetProcAddress(hNTDLL, "NtFreeVirtualMemory")))
                    break;
                if (!(NtOpenThread = (NTOPENTHREAD)GetProcAddress(hNTDLL, "NtOpenThread")))
                    break;
                if (!(RtlNtStatusToDosError = (RTLNTSTATUSTODOSERROR)GetProcAddress(hNTDLL, "RtlNtStatusToDosError")))
                    break;
                if (!(NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(hNTDLL, "NtQuerySystemInformation")))
                    break;
                if (!(NtQueryInformationProcess = (NTQUERYINFORMATIONPROCESS)GetProcAddress(hNTDLL, "NtQueryInformationProcess")))
                    break;
                if (!(NtQueryInformationThread = (NTQUERYINFORMATIONTHREAD)GetProcAddress(hNTDLL, "NtQueryInformationThread")))
                    break;

                // Win NT 4.0 or later
                if (OSMajorVersion >= 4)
                {
                    if (!(K32_VirtualAllocEx = (VIRTUALALLOCEX)GetProcAddress(hKernel32, "VirtualAllocEx")))
                        break;
                    if (!(K32_VirtualFreeEx = (VIRTUALFREEEX)GetProcAddress(hKernel32, "VirtualFreeEx")))
                        break;
                }

                // Win 2000 or later
                if (OSMajorVersion >= 5)
                {
                    if (!(K32_OpenThread = (OPENTHREAD)GetProcAddress(hKernel32, "OpenThread")))
                        break;
                    if (!(K32_CreateToolhelp32Snapshot = (CREATETOOLHELP32SNAPSHOT)GetProcAddress(hKernel32, "CreateToolhelp32Snapshot")))
                        break;
                    if (!(K32_Thread32First = (THREAD32FIRST)GetProcAddress(hKernel32, "Thread32First")))
                        break;
                    if (!(K32_Thread32Next = (THREAD32NEXT)GetProcAddress(hKernel32, "Thread32Next")))
                        break;
                }

                // Win 2003 or later
                if ((OSMajorVersion == 5 && OSMinorVersion >= 2) || OSMajorVersion == 6)
                {
                    if (!(K32_GetProcessId = (GETPROCESSID)GetProcAddress(hKernel32, "GetProcessId")))
                        break;
                    if (!(K32_GetThreadId = (GETTHREADID)GetProcAddress(hKernel32, "GetThreadId")))
                        break;
                }

                // Win Vista or later
                if (OSMajorVersion == 6)
                {
                if (!(NtCreateThreadEx = (NTCREATETHREADEX)GetProcAddress(hNTDLL, "NtCreateThreadEx")))
                    break;
                }
            }//WinNT

            Result = TRUE;
        } while(0);

        {
            if (hKernel32)
                FreeLibrary(hKernel32);
            if (hNTDLL)
                FreeLibrary(hNTDLL);

            bInitializing = FALSE;
        }
    } while(0);

    return Result;
}
