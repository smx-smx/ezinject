/*******************************************************************************
 * Injection Library                                                           *
 * Library that implements functions used in remote code injection.            *
 *                                                                             *
 * GetProcessInfo(): Returns info about a remote process.                      *
 * RemoteExecute(): Execute code in the context of a remote process.           *
 * InjectDll(): Inject a DLL into the address space of a remote process.       *
 * EjectDll(): Unload a DLL from the address space of a remote process.        *
 * StartRemoteSubclass(): Subclass a remote process window procedure.          *
 * StopRemoteSubclass(): Restore the remote process original window procedure. *
 *                                                                             *
 * (c) A. Miguel Feijao, 10/8/2005 - 1/11/2011                                 *
 *******************************************************************************/

/*******************************************************************************
 * VS2010 compilation notes:                                                   *
 * - Basic Runtime Checks = Default                                            *
 * - BufferSecurity Check = No (/GS-)                                          *
 *******************************************************************************/

#include <vadefs.h>
#define   DLL_EXPORT    // EXPORT functions

#define   WIN32_LEAN_AND_MEAN

#include  <windows.h>

#include  "Inject.h"
#include  "Remote.h"
#include  "Struct.h"
#include  "GetProcAddress.h"
#include  "LenDis.h"

/////////////////////////////////// GetProcessInfo() ///////////////////////////////////

/****************************************************************************
 * GetProcessInfo()                                                         *
 *                                                                          *
 * Return info about a running process.                                     *
 * The returned DWORD consists of two parts:                                *
 * The HIWORD contains the process subsystem:                               *
 *  0 = IMAGE_SUBSYSTEM_UNKNOWN                  (unknown process type)     *
 *  1 = IMAGE_SUBSYSTEM_NATIVE                   (native process)           *
 *  2 = IMAGE_SUBSYSTEM_WINDOWS_GUI              (GUI process)              *
 *  3 = IMAGE_SUBSYSTEM_WINDOWS_CUI              (character mode process)   *
 *  5 = IMAGE_SUBSYSTEM_OS2_CUI                  (OS/2 character process)   *
 *  7 = IMAGE_SUBSYSTEM_POSIX_CUI                (Posix character process)  *
 *  8 = IMAGE_SUBSYSTEM_NATIVE_WINDOWS           (Win9x driver)             *
 *  9 = IMAGE_SUBSYSTEM_WINDOWS_CE_GUI           (Windows CE process)       *
 * 10 = IMAGE_SUBSYSTEM_EFI_APPLICATION          (EFI Application)          *
 * 11 = IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  (EFI Boot Service Driver)  *
 * 12 = IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER       (EFI Runtime Driver)       *
 * 13 = IMAGE_SUBSYSTEM_EFI_ROM                  (EFI ROM)                  *
 * 14 = IMAGE_SUBSYSTEM_XBOX                     (XBox system)              *
 * 16 = IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION (Windows Boot Application) *
 * The LOWORD contains one or more flags:                                   *
 *  1 = fWIN9X           (Win 9x process)                                   *
 *  2 = fWINNT           (Win NT process)                                   *
 *  4 = fINVALID         (invalid process)                                  *
 *  8 = fDEBUGGED        (process is being debugged)                        *
 * 16 = fNOTINITIALIZED  (process didn't finished initialization)           *
 * 20 = fPROTECTED       (protected process)                                *
 * In case of error HIWORD=Error Code and LOWORD=-1                         *
 ****************************************************************************/
DWORD GetProcessInfo(DWORD dwPID)
{
    WORD                ProcessFlags = 0;	// Initialize to zero
    HANDLE              hProcess;
    uintptr_t           dwTID;
    PIMAGE_NT_HEADERS   pNTHeader;

    PPDB        pPDB;
    PTDB        pTDB;
    uintptr_t   *pThreadHead;
    PTHREADLIST pThreadNode;
    DWORD       TIBFlags;
    PVOID       pvStackUserTop;
    DWORD       StackUserTopContents;
    WORD        MTEIndex;
    PIMTE       pIMTE;

    PPEB        pPEB;
    PEB         PEB;
    BOOL        DebugPort;
	NTSTATUS    Status;
    PROCESS_BASIC_INFORMATION          pbi;
    PROCESS_EXTENDED_BASIC_INFORMATION ExtendedBasicInformation;

    do {
        /********* Win 9x *********/
        if (OSWin9x)
        {
            // Assume Win9x process
            ProcessFlags |= fWIN9X;

            // Get process handle
            if (!(hProcess = OpenProcess(PROCESS_VM_READ, FALSE, dwPID)))
                return MAKELONG(-1, ERROR_OPENPROCESS);

            // Pointer to PDB (Process Database)
            if (!(pPDB = GetPDB(dwPID)))
                return MAKELONG(-1, ERROR_GETPDB);

            // Process is being debugged
            if (((PPDB98)pPDB)->DebuggeeCB || ((PPDB98)pPDB)->Flags & fDebugSingle)
                ProcessFlags |= fDEBUGGED;

            // Termination status must be 0x103
            if (((PPDB98)pPDB)->TerminationStatus != 0x103)
                ProcessFlags |= fINVALID;

            // Invalid PDB flags
            if (((PPDB98)pPDB)->Flags & (fTerminated | fTerminating | fNearlyTerminating | fDosProcess | fWin16Process))
                ProcessFlags |= fINVALID;

            // Get thread list (from PDB)
            if (!(pThreadHead = (uintptr_t *)((PPDB98)pPDB)->ThreadList))
                return MAKELONG(-1, ERROR_THREADLIST);
            if (!(pThreadNode = (THREADLIST *)*pThreadHead))
                return MAKELONG(-1, ERROR_THREADLIST);

            // TDB of 1st (main) thread
            pTDB = (PTDB)pThreadNode->pTDB;

            // Check if TID is valid
            dwTID = (uintptr_t)pTDB ^ dwObsfucator;
            if (!IsThreadId(dwTID))
                return MAKELONG(-1, ERROR_ISTHREADID);

            // If pointers are bellow 0x80000000 process not initialized (?!?)
            // (c) R. Picha
            if ((uintptr_t)pThreadHead > 0 || (uintptr_t)pThreadNode > 0 || (uintptr_t)pTDB > 0)
                ProcessFlags |= fNOTINITIALIZED;

            // Get TIB flags
            if (OSWin95)
                TIBFlags = ((PTDB95)pTDB)->tib.TIBFlags;
            else if (OSWin98)
                TIBFlags = ((PTDB98)pTDB)->tib.TIBFlags;
            else if (OSWinMe)
                TIBFlags = ((PTDBME)pTDB)->tib.TIBFlags;
            else
                TIBFlags = 0;

            // Check if Win32 process initialized
            if (TIBFlags & TIBF_WIN32)
            {
                // Get top of stack
                if (OSWin95)
                    pvStackUserTop = ((PTDB95)pTDB)->tib.pvStackUserTop;
                else if (OSWin98)
                    pvStackUserTop = ((PTDB98)pTDB)->tib.pvStackUserTop;
                else if (OSWinMe)
                    pvStackUserTop = ((PTDBME)pTDB)->tib.pvStackUserTop;
                else
                    pvStackUserTop = NULL;

                // Last DWORD pushed on stack
                pvStackUserTop = (uintptr_t *)((uintptr_t)pvStackUserTop - sizeof(uintptr_t));

                // Read last DWORD pushed on stack
                if (!ReadProcessMemory(hProcess, pvStackUserTop, &StackUserTopContents, sizeof(StackUserTopContents), NULL))
                    return MAKELONG(-1, ERROR_READPROCESSMEMORY);

                // Process finished initialization if last DWORD on stack is < 0x80000000 (2GB)
                // (c) R. Picha
                if ((int)StackUserTopContents < 0)
                    ProcessFlags |= fNOTINITIALIZED;
            }

            // Get IMTE pointer for the process
            MTEIndex = ((PPDB98)pPDB)->MTEIndex;
            pIMTE = pMTEModTable[MTEIndex];

            // Get pointer to NTHeader from the IMTE
            pNTHeader = pIMTE->pNTHdr;
            if (pNTHeader->Signature != LOWORD(IMAGE_NT_SIGNATURE)) // "PE"
                return MAKELONG(-1, ERROR_INVALIDNTHEADER);

            CloseHandle(hProcess);

            // Return Subsystem + Process Flags
            return MAKELONG(ProcessFlags, pNTHeader->OptionalHeader.Subsystem);
        }

        /***** Win NT *****/
        else if (OSWinNT)
        {
            // Assume Win NT process
            ProcessFlags |= fWINNT;

			// Get process handle
            hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPID);

            // Get process Extended Basic Info (this will fail if Windows version is less than Vista)
			memset(&ExtendedBasicInformation, 0, sizeof(ExtendedBasicInformation));
			ExtendedBasicInformation.Size = sizeof(PROCESS_EXTENDED_BASIC_INFORMATION);
            NtQueryInformationProcess(hProcess,
                                      ProcessBasicInformation,
                                      &ExtendedBasicInformation,
                                      sizeof(ExtendedBasicInformation),
                                      NULL);

            CloseHandle(hProcess);

			// Protected process
			if (ExtendedBasicInformation.IsProtectedProcess)
			{
				ProcessFlags |= fPROTECTED;
				return MAKELONG(ProcessFlags, IMAGE_SUBSYSTEM_UNKNOWN);
			}

            // Get process handle
            if (!(hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPID)))
                return MAKELONG(-1, ERROR_OPENPROCESS);

            // Get Debug port status
            Status = NtQueryInformationProcess(hProcess,
                                               ProcessDebugPort,
                                               &DebugPort,
                                               sizeof(DebugPort),
                                               NULL);

            if (!NT_SUCCESS(Status))
                return MAKELONG(-1, ERROR_NTQUERYINFORMATIONPROCESS);

            // Process is being debugged
            if (DebugPort)
                ProcessFlags |= fDEBUGGED;

            // Get PEB base address of process
            Status = NtQueryInformationProcess(hProcess,
                                               ProcessBasicInformation,
                                               &pbi,
                                               sizeof(pbi),
                                               NULL);

            if (!NT_SUCCESS(Status))
                return MAKELONG(-1, ERROR_NTQUERYINFORMATIONPROCESS);

            // Exit status must be 0x103
            if (pbi.ExitStatus != 0x103)
                ProcessFlags |= fINVALID;

            // Read PEB
            // (for local process this is the same as FS:[0x30])
            pPEB = pbi.PebBaseAddress;
            if (pPEB == NULL)
            {
                ProcessFlags |= fINVALID;
                return MAKELONG(ProcessFlags, IMAGE_SUBSYSTEM_NATIVE);
            }
            else
            {
                if (!ReadProcessMemory(hProcess, pPEB, &PEB, sizeof(PEB), NULL))
                    return MAKELONG(-1, ERROR_READPROCESSMEMORY);

                // Process is being debugged
                if (PEB.BeingDebugged)
                    ProcessFlags |= fDEBUGGED;

                // Process not yet initialized
                if (!PEB.Ldr || !PEB.LoaderLock)
                    ProcessFlags |= fNOTINITIALIZED;
            }

            CloseHandle(hProcess);

            // Return Subsystem + Process Flags
            return MAKELONG(ProcessFlags, PEB.ImageSubsystem);
        }
        else
            return MAKELONG(-1, ERROR_INVALIDOS);
    } while(0);
}


/////////////////////////// RemoteExecute() ////////////////////////////

/****************************************
 * InitializeAndPatchStub()             *
 *                                      *
 * Patches remote stub data at runtime. *
 ****************************************/
int InitializeAndPatchStub(HANDLE hProcess, PBYTE pCode, OFFSETS offs, uintptr_t UserFunc, DWORD Native)
{
    SIZE_T   nBytesWritten = 0;
    BOOL    fFinished = FALSE;

    if (OSWin9x)
    {
        *(uintptr_t *)(pCode + offs.PUserFunc) = UserFunc;
        *(uintptr_t *)(pCode + offs.PLdrShutdownThread) = (uintptr_t)LdrShutdownThread;
        *(uintptr_t *)(pCode + offs.PNtFreeVirtualMemory) = (uintptr_t)NtFreeVirtualMemory;
        *(uintptr_t *)(pCode + offs.PNtTerminateThread) = (uintptr_t)NtTerminateThread;
        *(uintptr_t *)(pCode + offs.PNative) = Native;
        *(uintptr_t *)(pCode + offs.PFinished) = FALSE;
        return 0;
    }
    else
    {
        if (!WriteProcessMemory(hProcess, pCode + offs.PUserFunc, &UserFunc, sizeof(UserFunc), &nBytesWritten) ||
            nBytesWritten != sizeof(UserFunc))
            return -1;
        if (!WriteProcessMemory(hProcess, pCode + offs.PLdrShutdownThread, &LdrShutdownThread,
            sizeof(LdrShutdownThread), &nBytesWritten) || nBytesWritten != sizeof(LdrShutdownThread))
            return -1;
        if (!WriteProcessMemory(hProcess, pCode + offs.PNtFreeVirtualMemory, &NtFreeVirtualMemory,
            sizeof(NtFreeVirtualMemory), &nBytesWritten) || nBytesWritten != sizeof(NtFreeVirtualMemory))
            return -1;
        if (!WriteProcessMemory(hProcess, pCode + offs.PNtTerminateThread, &NtTerminateThread,
            sizeof(NtTerminateThread), &nBytesWritten) || nBytesWritten != sizeof(NtTerminateThread))
            return -1;
        if (!WriteProcessMemory(hProcess, pCode + offs.PNative, &Native, sizeof(Native), &nBytesWritten) ||
            nBytesWritten != sizeof(Native))
            return -1;
        if (!WriteProcessMemory(hProcess, pCode + offs.PFinished, &fFinished, sizeof(fFinished), &nBytesWritten) ||
            nBytesWritten != sizeof(fFinished))
            return -1;
        return 0;
    }
}

void __stdcall GetOffsets(POFFSETS offs){
    //$TODO: replace with ezinject
}

/****************************************************
 * RemoteExecute()                                  *
 *                                                  *
 * Execute code in the context of a remote process. *
 * Return zero if everything went ok or error code. *
 ****************************************************/
int RemoteExecute(HANDLE hProcess,                      // Remote process handle
                  DWORD  ProcessFlags,                  // ProcessFlags returned by GetProcessInfo()
                  LPTHREAD_START_ROUTINE Function,      // Remote thread function
                  PVOID  pData,                         // User data passed to remote thread
                  DWORD  Size,                          // Size of user data block (0=treat pData as DWORD)
                  DWORD  dwTimeout,                     // Timeout value
                  PDWORD ExitCode)                      // Return exit code from remote code
{
    PBYTE       pStubCode = NULL;
    PBYTE       pRemoteCode = NULL;
    PBYTE       pRemoteData = NULL;
    PVOID       pParams = NULL;
    DWORD       FunctionSize;
    SIZE_T      nBytesWritten = 0, nBytesRead = 0;
    HANDLE      hThread = NULL;
    DWORD       dwThreadId;
    DWORD       dwExitCode = -1;
    int         ErrorCode = 0;
    DWORD       dwCreationFlags = 0; // dwCreationFlags parameter for CreateRemoteThread()
    NTSTATUS    Status;
    BOOL        fNative;
    BOOL        fFinished;
    DWORD       dwTmpTimeout = 100;	// 100 ms
    OFFSETS     StubOffs;

    PBYTE       data;
	DWORD       offset;

    do {
        do {
            // Initialize ExitCode to -1
            if (ExitCode)
                *ExitCode = -1;

            // ProcessFlags = 0 ?
            if (!ProcessFlags)
                ProcessFlags = GetProcessInfo(_GetProcessId(hProcess));

            // Invalid Process flags
            if (ProcessFlags & fINVALID)
            {
                ErrorCode = ERROR_INVALIDPROCESS;
                break;
            }

            // Get ASM code offsets
            GetOffsets(&StubOffs);

            // a fix for function addresses pointing to "JMP "
            data = (PBYTE)Function;
            if (*data == 0xE9) // JMP => a thunk
			{
               offset = *(PDWORD)(data + 1);
               data = data + 5 + offset;
               Function = (LPTHREAD_START_ROUTINE)data;
			}

            // Allocate memory for function in remote process
            if (!(pRemoteCode = _VirtualAllocEx(hProcess, 0, FunctionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
            {
                ErrorCode = ERROR_VIRTUALALLOCEX;
                break;
            }

            // Copy function code to remote process
            if (!WriteProcessMemory(hProcess, pRemoteCode, Function, FunctionSize, &nBytesWritten) ||
                nBytesWritten != FunctionSize)
            {
                ErrorCode = ERROR_WRITEPROCESSMEMORY;
                break;
            }

            // Data block specified ?
            if (pData && Size)
            {
                // Allocate memory for data block in remote process
                if (!(pRemoteData = _VirtualAllocEx(hProcess, 0, Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
                {
                    ErrorCode = ERROR_VIRTUALALLOCEX;
                    break;
                }

                // Copy data block to remote process
                if (!WriteProcessMemory(hProcess, pRemoteData, pData, Size, &nBytesWritten) || nBytesWritten != Size)
                {
                    ErrorCode = ERROR_WRITEPROCESSMEMORY;
                    break;
                }

                pParams = pRemoteData;
            }
            // Pass value directly to CreateThread()
            else
                pParams = pData;

            // Size of stub code
            FunctionSize = StubOffs.StubSize;

            // Allocate memory for stub code in remote process
            if (!(pStubCode = _VirtualAllocEx(hProcess, 0, FunctionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
            {
                ErrorCode = ERROR_VIRTUALALLOCEX;
                break;
            }

            // Copy stub code to remote process
            if (!WriteProcessMemory(hProcess, pStubCode, (LPVOID)StubOffs.StubStart,
                 FunctionSize, &nBytesWritten) || nBytesWritten != FunctionSize)
            {
                ErrorCode = ERROR_WRITEPROCESSMEMORY;
                break;
            }

			// NT native process requires a different stub exit code
            fNative = ((HIWORD(ProcessFlags) == IMAGE_SUBSYSTEM_NATIVE) && (ProcessFlags & fWINNT));

            // Patch Stub data
            if (InitializeAndPatchStub(hProcess, pStubCode, StubOffs, (uintptr_t)pRemoteCode, fNative) != 0)
            {
                ErrorCode = ERROR_PATCH;
                break;
            }

            // Process not initialized
            if (ProcessFlags & fNOTINITIALIZED)
            {
                // Win9x
                if (ProcessFlags & fWIN9X)
                {
                    dwCreationFlags |= CREATE_SILENT;
                    ProcessFlags &= ~fNOTINITIALIZED;       // Goto initialized
                }

                // WinNT
                else if (ProcessFlags & fWINNT)
                {
                    if(OSWinNT3){
                        // $FIXME: Windows NT 3
                        // (note: ezinject currently works by thread hijacking)
                        ErrorCode = ERROR_INVALIDOS;
                        break;
                    }

                    if (!(dwThreadId = _GetProcessThread(_GetProcessId(hProcess))))
                    {
                        ProcessFlags |= ~fNOTINITIALIZED;
                        goto Initialized;					// Try initialized
                    }

                    if (!(hThread = _OpenThread(THREAD_SET_CONTEXT, FALSE, dwThreadId)))
                    {
                        ProcessFlags |= ~fNOTINITIALIZED;
                        goto Initialized;					// Try initialized
                    }

                    Status = NtQueueApcThread(hThread,                      // hThread
                                              (PKNORMAL_ROUTINE)pStubCode,  // APC Routine
                                              pParams,                      // Argument 1
                                              NULL,                         // Argument 2
                                              NULL);                        // Argument 3

                    if (!NT_SUCCESS(Status))
                    {
                        ProcessFlags |= ~fNOTINITIALIZED;
                        goto Initialized;					// Try initialized
                    }

                    // Wait for remote code to finish
                    dwTmpTimeout = min(dwTmpTimeout, dwTimeout);
                    for (fFinished = FALSE; !fFinished && dwTimeout != 0; dwTimeout -= min(dwTmpTimeout, dwTimeout))
                    {
                        WaitForSingleObject(GetCurrentThread(), dwTmpTimeout);
                        if (!ReadProcessMemory(hProcess, pStubCode + StubOffs.PFinished, &
                                               fFinished, sizeof(fFinished), &nBytesRead) || nBytesRead != sizeof(fFinished))
                        {
                            ErrorCode = ERROR_READPROCESSMEMORY;
                            break;
                        }
                    }

                    // Timeout ocurred
                    if (dwTimeout == 0 && !fFinished)
                        ErrorCode = ERROR_WAITTIMEOUT;

                    // Doesn't make sense to GetExitCodeThread() on a "hijacked" thread !
                    dwExitCode = 0;
                }/*Win NT*/
            }/*Not initialized*/

Initialized:
            // Initialized process
            if (!(ProcessFlags & fNOTINITIALIZED))
            {
                // NT native
                if (fNative)
                {
                    Status = RtlCreateUserThread(hProcess,      // hProcess
                                                 NULL,          // &SecurityDescriptor
                                                 FALSE,         // CreateSuspended
                                                 0,             // StackZeroBits
                                                 NULL,          // StackReserved
                                                 NULL,          // StackCommit
                                                 pStubCode,     // StartAddress
                                                 pParams,       // StartParameter
                                                 &hThread,      // &hThread
                                                 NULL);         // &ClientId

                    if (!NT_SUCCESS(Status))
                    {
                        SetLastError(RtlNtStatusToDosError(Status));
                        ErrorCode = ERROR_RTLCREATETHREAD;
                        break;
                    }
                }

                // Win32 process
                else
                    // Create remote thread
                    hThread = _CreateRemoteThread(hProcess,
                                                  NULL,
                                                  0,
                                                  (LPTHREAD_START_ROUTINE)pStubCode,
                                                  pParams,
                                                  dwCreationFlags,
                                                  &dwThreadId);


                // Error in creating thread
                if (!hThread)
                {
                    ErrorCode = ERROR_CREATETHREAD;
                    break;
                }

                // Wait for thread to terminate
                if (WaitForSingleObject(hThread, dwTimeout) != WAIT_OBJECT_0)
                {
                    ErrorCode = ERROR_WAITTIMEOUT;
                    break;
                }

                // Get thread exit code
                GetExitCodeThread(hThread, &dwExitCode);
            }/*Initialized*/

            // Data block specified ?
            if (pData && Size)
            {
                // Read back remote data block
                if (!ReadProcessMemory(hProcess, pRemoteData, pData, Size, &nBytesRead) || nBytesRead != Size)
                {
                    ErrorCode = ERROR_READPROCESSMEMORY;
                    break;
                }
            }
        } while(0);

        // Cleanup
        {
            if (pStubCode)
                _VirtualFreeEx(hProcess, pStubCode, 0, MEM_RELEASE);
            if (pRemoteCode)
                _VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
            if (pRemoteData)
                _VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
            if (hThread)
                CloseHandle(hThread);
        }
    } while(0);

    // Return remote stub exit code
    if (ExitCode)
        *ExitCode = dwExitCode;

    // Return RemoteExecute() error code or remote code exception code
    if ((ErrorCode == 0) && (dwExitCode & REMOTE_EXCEPTION))
        return dwExitCode;
    else
        return ErrorCode;
}

/////////////////////////// InjectDll() ////////////////////////////

/****************************
 * Remote InjectDll thread. *
 ****************************/
static DWORD WINAPI RemoteInjectDll(PRDATADLL pData)
{
    pData->hRemoteDll = pData->LoadLibrary(pData->szDll);

    if (pData->hRemoteDll == NULL)
        pData->Result = -1;
    else
        pData->Result = 0; // 0 = OK

    return pData->Result;
}


/**********************************************************
 * Load a Dll into the address space of a remote process. *
 * (ANSI version)                                         *
 **********************************************************/
int InjectDllA(HANDLE    hProcess,       // Remote process handle
               DWORD     ProcessFlags,   // ProcessFlags returned by GetProcessInfo()
               LPCSTR    szDllPath,      // Path of Dll to load
               DWORD     dwTimeout,      // Timeout value
               HINSTANCE *hRemoteDll)    // Return handle of loaded Dll
{
    int       rc;
    int       ErrorCode = 0;
    DWORD     ExitCode = -1;
    HINSTANCE hKernel32 = 0;
    RDATADLL  rdDll;

    do {
        do {
            // Load Kernel32.dll
            if (!(hKernel32 = LoadLibraryA("Kernel32.dll")))
            {
                ErrorCode = ERROR_LOADLIBRARY;
                break;
            }

            // Initialize data block passed to RemoteInjectDll()
            rdDll.Result = -1;
            rdDll.hRemoteDll = NULL;
            lstrcpyA(rdDll.szDll, szDllPath);
            rdDll.LoadLibrary = (LOADLIBRARY)GetProcAddress(hKernel32, "LoadLibraryA");

            if (!rdDll.LoadLibrary)
            {
                ErrorCode = ERROR_GETPROCADDRESS;
                break;
            }

            // Execute RemoteInjectDll() in remote process
            rc = RemoteExecute(hProcess,
                               ProcessFlags,
                               (LPTHREAD_START_ROUTINE)RemoteInjectDll,
                               &rdDll,
                               sizeof(rdDll),
                               dwTimeout,
                               &ExitCode);
        } while(0);

        {
            if (hKernel32)
                FreeLibrary(hKernel32);
        }
    } while(0);

    // Return handle of loaded dll
    if (hRemoteDll)
        *hRemoteDll = rdDll.hRemoteDll;

    // Return error code
    if (ErrorCode == 0 && rc != 0)
        return rc;
    else if (ErrorCode == 0 && ExitCode != 0)
        return ERROR_REMOTE;
    else
        return ErrorCode;
}


/**********************************************************
 * Load a Dll into the address space of a remote process. *
 * (Unicode version)                                      *
 **********************************************************/
int InjectDllW(HANDLE    hProcess,       // Remote process handle
               DWORD     ProcessFlags,   // ProcessFlags returned by GetProcessInfo()
               LPCWSTR   szDllPath,      // Path of Dll to load
               DWORD     dwTimeout,      // Timeout value
               HINSTANCE *hRemoteDll)    // Return handle of loaded Dll
{
    char DllPath[MAX_PATH + 1];

	// Convert from Unicode to Ansi
    *DllPath = '\0';
    WideCharToMultiByte(CP_ACP, 0, szDllPath, -1, DllPath, MAX_PATH, NULL, NULL);

    return InjectDllA(hProcess, ProcessFlags, DllPath, dwTimeout, hRemoteDll);
}

/****************************
 * Remote EjectDll thread. *
 ****************************/
/*
static DWORD WINAPI RemoteEjectDll(PRDATADLL pData)
{
    if (pData->szDll[0] != '\0')
        pData->hRemoteDll = pData->GetModuleHandle(pData->szDll);

    pData->Result = pData->FreeLibrary(pData->hRemoteDll);

    return (pData->Result == 0); // 0 = OK
}
*/

static DWORD WINAPI RemoteEjectDll(PRDATADLL pData)
{
    int i = 0;

    do
    {
        if (pData->szDll[0] != '\0')
            pData->hRemoteDll = pData->GetModuleHandle(pData->szDll);

        pData->Result = pData->FreeLibrary(pData->hRemoteDll);
        i++;
    } while (pData->Result);

    return (i > 1 ? 0 : -1); // 0 = OK
}


/************************************************************
 * Unload a Dll from the address space of a remote process. *
 * (ANSI version)                                           *
 ************************************************************/
int EjectDllA(HANDLE     hProcess,       // Remote process handle
              DWORD      ProcessFlags,   // ProcessFlags returned by GetProcessInfo()
              LPCSTR     szDllPath,      // Path of Dll to unload
              HINSTANCE  hRemoteDll,     // Dll handle
              DWORD      dwTimeout)      // Timeout value
{
    int       rc;
    int       ErrorCode = 0;
    DWORD     ExitCode = -1;
    HINSTANCE hKernel32 = 0;
    RDATADLL  rdDll;

    do {
        do {
            // Load Kernel32.dll
            if (!(hKernel32 = LoadLibraryA("Kernel32.dll")))
            {
                ErrorCode = ERROR_LOADLIBRARY;
                break;
            }

            // Initialize data block passed to RemoteInjectDll()
            rdDll.Result = -1;
            rdDll.hRemoteDll = hRemoteDll;
            if (szDllPath)
                lstrcpyA(rdDll.szDll, szDllPath);
            rdDll.FreeLibrary = (FREELIBRARY)GetProcAddress(hKernel32, "FreeLibrary");
            rdDll.GetModuleHandle = (GETMODULEHANDLE)GetProcAddress(hKernel32, "GetModuleHandleA");

            if (!rdDll.FreeLibrary || !rdDll.GetModuleHandle)
            {
                ErrorCode = ERROR_GETPROCADDRESS;
                break;
            }

            // Execute RemoteEjectDll() in remote process
            rc = RemoteExecute(hProcess,
                               ProcessFlags,
                               (LPTHREAD_START_ROUTINE)RemoteEjectDll,
                               &rdDll,
                               sizeof(rdDll),
                               dwTimeout,
                               &ExitCode);
        } while(0);

        if (hKernel32){
            FreeLibrary(hKernel32);
        }
    } while(0);

    // Return error code
    if (ErrorCode == 0 && rc != 0)
        return rc;
    else if (ErrorCode == 0 && ExitCode != 0)
        return ERROR_REMOTE;
    else
        return ErrorCode;
}


/************************************************************
 * Unload a Dll from the address space of a remote process. *
 * (Unicode version)                                        *
 ************************************************************/
int EjectDllW(HANDLE     hProcess,       // Remote process handle
              DWORD      ProcessFlags,   // ProcessFlags returned by GetProcessInfo()
              LPCWSTR    szDllPath,      // Path of Dll to unload
              HINSTANCE  hRemoteDll,     // Dll handle
              DWORD      dwTimeout)      // Timeout value
{
    char DllPath[MAX_PATH + 1];

	// Convert from Unicode to Ansi
    *DllPath = '\0';
    WideCharToMultiByte(CP_ACP, 0, szDllPath, -1, DllPath, MAX_PATH, NULL, NULL);

    return EjectDllA(hProcess, ProcessFlags, DllPath, hRemoteDll, dwTimeout);
}

/************************************************
 * InitializeAndPatchStubWndProc()               *
 *                                               *
 * Patches remote StubWndProc() data at runtime. *
 *************************************************/
int InitializeAndPatchStubWndProc(HANDLE hProcess, PBYTE pCode, OFFSETS offs, DWORD pRDATA)
{
    SIZE_T   nBytesWritten = 0;

    if (OSWin9x)
    {
        *(uintptr_t *)(pCode + offs.pRDATA) = pRDATA;
        return 0;
    }
    else
    {
        if (!WriteProcessMemory(hProcess, pCode + offs.pRDATA, &pRDATA, sizeof(pRDATA), &nBytesWritten) ||
            nBytesWritten != sizeof(pRDATA))
            return -1;
        return 0;
    }
}

/////////////////////////////////////// DllMain ///////////////////////////////////////////

BOOL WINAPI DllMain(HINSTANCE hinstDLL,  // Handle to DLL module
                    DWORD fdwReason,     // Reason for calling function
                    LPVOID lpReserved )  // Reserved
{
    // Perform actions based on the reason for calling
    switch(fdwReason)
    {
        // Initialize once for each new process
        // Return FALSE to fail DLL load
        case DLL_PROCESS_ATTACH:
             // Disable DLL_THREAD_ATTACH and DLL_THREAD_DETACH messages
             DisableThreadLibraryCalls(hinstDLL);

             return Initialization();
             break;

             // Do thread-specific initialization
        case DLL_THREAD_ATTACH:
             break;

             // Do thread-specific cleanup
        case DLL_THREAD_DETACH:
             break;

             // Perform any necessary cleanup
        case DLL_PROCESS_DETACH:
             break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH
}
