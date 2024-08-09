/*********************************************************************
 * Structures and definitions undocumented or included in the NTDDK. *
 *********************************************************************/

#ifndef __STRUCT_H__
#define __STRUCT_H__

#include <processthreadsapi.h>

/////////////////////// Windows NT /////////////////////////

typedef PVOID *PPVOID;
typedef LONG NTSTATUS, *PNTSTATUS;
typedef LONG KPRIORITY;

typedef void (CALLBACK *PKNORMAL_ROUTINE)(PVOID, PVOID, PVOID);

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;


// Object attributes

#define OBJ_INHERIT            0x00000002
#define OBJ_PERMANENT          0x00000010
#define OBJ_EXCLUSIVE          0x00000020
#define OBJ_CASE_INSENSITIVE   0x00000040
#define OBJ_OPENIF             0x00000080
#define OBJ_OPENLINK           0x00000100
#define OBJ_KERNEL_HANDLE      0x00000200
#define OBJ_FORCE_ACCESS_CHECK 0x00000400
#define OBJ_VALID_ATTRIBUTES   0x000007f2

typedef struct _OBJECT_ATTRIBUTES {
       ULONG Length;
       HANDLE RootDirectory;
       PUNICODE_STRING ObjectName;
       ULONG Attributes;
       PSECURITY_DESCRIPTOR SecurityDescriptor;
       PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef const OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
    }

typedef struct RTL_DRIVE_LETTER_CURDIR {
    USHORT          Flags;
    USHORT          Length;
    ULONG           TimeStamp;
    UNICODE_STRING  DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, *PCURDIR;

#define RTL_MAX_DRIVE_LETTERS 32

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG EnvironmentSize;
    ULONG EnvironmentVersion;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    HANDLE     SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID      EntryInProgress;
    BOOLEAN    ShutdownInProgress;
    HANDLE     ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

#define GDI_HANDLE_BUFFER_SIZE32 34
#define GDI_HANDLE_BUFFER_SIZE64 60

#ifndef WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#endif

typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

#define FLS_MAXIMUM_AVAILABLE 128

#define GDI_BATCH_BUFFER_SIZE 310

typedef struct _GDI_TEB_BATCH {
    ULONG Offset;
    ULONG_PTR HDC;
    ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
    ULONG Flags;
    PSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME {
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME *Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation, // 0, q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    ProcessIoCounters, // q: IO_COUNTERS
    ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX
    ProcessTimes, // q: KERNEL_USER_TIMES
    ProcessBasePriority, // s: KPRIORITY
    ProcessRaisePriority, // s: ULONG
    ProcessDebugPort, // q: HANDLE
    ProcessExceptionPort, // s: HANDLE
    ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
    ProcessLdtInformation, // 10
    ProcessLdtSize,
    ProcessDefaultHardErrorMode, // qs: ULONG
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
    ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
    ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
    ProcessWx86Information,
    ProcessHandleCount, // 20, q: ULONG, PROCESS_HANDLE_INFORMATION
    ProcessAffinityMask, // s: KAFFINITY
    ProcessPriorityBoost, // qs: ULONG
    ProcessDeviceMap,
    ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
    ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
    ProcessWow64Information, // q: ULONG_PTR
    ProcessImageFileName, // q: UNICODE_STRING
    ProcessLUIDDeviceMapsEnabled, // q: ULONG
    ProcessBreakOnTermination, // qs: ULONG
    ProcessDebugObjectHandle, // 30, q: HANDLE
    ProcessDebugFlags, // qs: ULONG
    ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
    ProcessIoPriority, // qs: ULONG
    ProcessExecuteFlags, // qs: ULONG
    ProcessResourceManagement,
    ProcessCookie, // q: ULONG
    ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
    ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION
    ProcessPagePriority, // q: ULONG
    ProcessInstrumentationCallback, // 40
    ProcessThreadStackAllocation, // qs: PROCESS_STACK_ALLOCATION_INFORMATION
    ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
    ProcessImageFileNameWin32, // q: UNICODE_STRING
    ProcessImageFileMapping, // q: HANDLE (input)
    ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
    ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
    ProcessGroupInformation, // q: USHORT[]
    ProcessTokenVirtualizationEnabled, // s: ULONG
    ProcessConsoleHostProcess, // q: ULONG_PTR
    ProcessWindowInformation, // 50, q: PROCESS_WINDOW_INFORMATION
    ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    ProcessMitigationPolicy, // qs: PROCESS_MITIGATION_POLICY_INFORMATION
    ProcessDynamicFunctionTableInformation,
    ProcessHandleCheckingMode,
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
    ThreadTimes, // q: KERNEL_USER_TIMES
    ThreadPriority, // s: KPRIORITY
    ThreadBasePriority, // s: LONG
    ThreadAffinityMask, // s: KAFFINITY
    ThreadImpersonationToken, // s: HANDLE
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
    ThreadEventPair,
    ThreadQuerySetWin32StartAddress, // q: PVOID
    ThreadZeroTlsCell, // 10
    ThreadPerformanceCount, // q: LARGE_INTEGER
    ThreadAmILastThread, // q: ULONG
    ThreadIdealProcessor, // s: ULONG
    ThreadPriorityBoost, // qs: ULONG
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending, // q: ULONG
    ThreadHideFromDebugger, // s: void
    ThreadBreakOnTermination, // qs: ULONG
    ThreadSwitchLegacyState,
    ThreadIsTerminated, // 20, q: ULONG
    ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
    ThreadIoPriority, // qs: ULONG
    ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION
    ThreadPagePriority, // q: ULONG
    ThreadActualBasePriority,
    ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
    ThreadCSwitchMon,
    ThreadCSwitchPmu,
    ThreadWow64Context, // q: WOW64_CONTEXT
    ThreadGroupInformation, // 30, q: GROUP_AFFINITY
    ThreadUmsInformation,
    ThreadCounterProfiling,
    ThreadIdealProcessorEx, // q: PROCESSOR_NUMBER
    ThreadCpuAccountingInformation, // since WIN8
    MaxThreadInfoClass
} THREADINFOCLASS;

// PEB (Process Environment Block) data structure (FS:[0x30])
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsLegacyProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN SpareBits : 3;
        };
    };
    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ReservedBits0 : 27;
        };
        ULONG EnvironmentUpdateCount;
    };
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved[1];
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID HotpatchInformation;
    PPVOID ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    LARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PPVOID ProcessHeaps;

    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;

    PRTL_CRITICAL_SECTION LoaderLock;

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ImageProcessAffinityMask;
    GDI_HANDLE_BUFFER GdiHandleBuffer;
    PVOID PostProcessInitRoutine;

    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];

    ULONG SessionId;

    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;

    UNICODE_STRING CSDVersion;

    PVOID ActivationContextData;
    PVOID ProcessAssemblyStorageMap;
    PVOID SystemDefaultActivationContextData;
    PVOID SystemAssemblyStorageMap;

    SIZE_T MinimumStackCommit;

    PPVOID FlsCallback;
    LIST_ENTRY FlsListHead;
    PVOID FlsBitmap;
    ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
    ULONG FlsHighIndex;

    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
    PVOID pContextData;
    PVOID pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG SpareTracingBits : 30;
        };
    };
} PEB, *PPEB;

// TEB (Thread Environment Block) data structure (FS:[0x18])
typedef struct _TEB {
    NT_TIB NtTib;

    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;

    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    PVOID WOW32Reserved;
    LCID CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    PVOID SystemReserved1[54];
    NTSTATUS ExceptionCode;
    PVOID ActivationContextStackPointer;
#ifdef _M_X64
    UCHAR SpareBytes[24];
#else
    UCHAR SpareBytes[36];
#endif
    ULONG TxFsContext;

    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    ULONG_PTR Win32ClientInfo[62];
    PVOID glDispatchTable[233];
    ULONG_PTR glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;

    NTSTATUS LastStatusValue;
    UNICODE_STRING StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[261];

    PVOID DeallocationStack;
    PVOID TlsSlots[64];
    LIST_ENTRY TlsLinks;

    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID DbgSsReserved[2];

    ULONG HardErrorMode;
#ifdef _M_X64
    PVOID Instrumentation[11];
#else
    PVOID Instrumentation[9];
#endif
    GUID ActivityId;

    PVOID SubProcessTag;
    PVOID EtwLocalData;
    PVOID EtwTraceData;
    PVOID WinSockData;
    ULONG GdiBatchCount;

    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        };
    };

    ULONG GuaranteedStackBytes;
    PVOID ReservedForPerf;
    PVOID ReservedForOle;
    ULONG WaitingOnLoaderLock;
    PVOID SavedPriorityState;
    ULONG_PTR SoftPatchPtr1;
    PVOID ThreadPoolData;
    PPVOID TlsExpansionSlots;
#ifdef _M_X64
    PVOID DeallocationBStore;
    PVOID BStoreLimit;
#endif
    ULONG MuiGeneration;
    ULONG IsImpersonating;
    PVOID NlsCache;
    PVOID pShimData;
    ULONG HeapVirtualAffinity;
    HANDLE CurrentTransactionHandle;
    PTEB_ACTIVE_FRAME ActiveFrame;
    PVOID FlsData;

    PVOID PreferredLanguages;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;

    union
    {
        USHORT CrossTebFlags;
        USHORT SpareCrossTebBits : 16;
    };
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;
            USHORT HasFiberData : 1;
            USHORT SkipThreadAttach : 1;
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;
            USHORT ClonedThread : 1;
            USHORT SuppressDebugMsg : 1;
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;
            USHORT SpareSameTebBits : 1;
        };
    };

    PVOID TxnScopeEnterCallback;
    PVOID TxnScopeExitCallback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    ULONG SpareUlong0;
    PVOID ResourceRetValue;
} TEB, *PTEB;

// Structured Exception Handler
typedef struct _SEH {
    struct _SEH *pNext;
    FARPROC     pfnHandler;
} SEH, *PSEH;

#define SystemProcessesAndThreadsInformation    5
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PPEB      PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    HANDLE    UniqueProcessId;
    HANDLE    InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef struct _PROCESS_EXTENDED_BASIC_INFORMATION {
    SIZE_T Size; // set to sizeof structure on input
    PROCESS_BASIC_INFORMATION BasicInfo;
    union
    {
        ULONG Flags;
        struct
        {
            ULONG IsProtectedProcess : 1;
            ULONG IsWow64Process : 1;
            ULONG IsProcessDeleting : 1;
            ULONG IsCrossSessionCreate : 1;
            ULONG SpareBits : 28;
        };
    };
} PROCESS_EXTENDED_BASIC_INFORMATION, *PPROCESS_EXTENDED_BASIC_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PTEB      TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    KPRIORITY Priority;
    LONG      BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef enum _KWAIT_REASON {
    Executive,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrEventPair,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    WrKeyedEvent,
    WrTerminated,
    WrProcessInSwap,
    WrCpuRateControl,
    WrCalloutStack,
    WrKernel,
    WrResource,
    WrPushLock,
    WrMutex,
    WrQuantumEnd,
    WrDispatchInt,
    WrPreempted,
    WrYieldExecution,
    WrFastMutex,
    WrGuardedMutex,
    WrRundown,
    MaximumWaitReason
} KWAIT_REASON, *PKWAIT_REASON;

typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

// The size of the SYSTEM_PROCESS_INFORMATION structure is
// different on NT 4 and Win2K.

typedef struct _VM_COUNTERS {
    SIZE_T          PeakVirtualSize;
    SIZE_T          VirtualSize;
    ULONG           PageFaultCount;
    SIZE_T          PeakWorkingSetSize;
    SIZE_T          WorkingSetSize;
    SIZE_T          QuotaPeakPagedPoolUsage;
    SIZE_T          QuotaPagedPoolUsage;
    SIZE_T          QuotaPeakNonPagedPoolUsage;
    SIZE_T          QuotaNonPagedPoolUsage;
    SIZE_T          PagefileUsage;
    SIZE_T          PeakPagefileUsage;
} VM_COUNTERS;

typedef struct _SYSTEM_PROCESS_INFORMATION_NT4 {
    ULONG           NextEntryOffset;
    ULONG           NumberOfThreads;
    ULONG           Reserved1[6];
    LARGE_INTEGER   CreateTime;
    LARGE_INTEGER   UserTime;
    LARGE_INTEGER   KernelTime;
    UNICODE_STRING  ImageName;
    KPRIORITY       BasePriority;
    HANDLE          UniqueProcessId;
    HANDLE          InheritedFromUniqueProcessId;
    ULONG           HandleCount;
    ULONG           Reserved2[2];
    VM_COUNTERS     VmCounters;
    SYSTEM_THREAD_INFORMATION  Threads[1];
} SYSTEM_PROCESS_INFORMATION_NT4, *PSYSTEM_PROCESS_INFORMATION_NT4;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  WorkingSetPrivateSize;         // since VISTA
    ULONG          HardFaultCount;                // since WIN7
    ULONG          NumberOfThreadsHighWatermark;  // since WIN7
    ULONGLONG      CycleTime;                     // since WIN7
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY      BasePriority;
    HANDLE         UniqueProcessId;
    HANDLE         InheritedFromUniqueProcessId;
    ULONG          HandleCount;
    ULONG          SessionId;
    ULONG_PTR      UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
    SIZE_T         PeakVirtualSize;
    SIZE_T         VirtualSize;
    ULONG          PageFaultCount;
    SIZE_T         PeakWorkingSetSize;
    SIZE_T         WorkingSetSize;
    SIZE_T         QuotaPeakPagedPoolUsage;
    SIZE_T         QuotaPagedPoolUsage;
    SIZE_T         QuotaPeakNonPagedPoolUsage;
    SIZE_T         QuotaNonPagedPoolUsage;
    SIZE_T         PagefileUsage;
    SIZE_T         PeakPagefileUsage;
    SIZE_T         PrivatePageCount;
    LARGE_INTEGER  ReadOperationCount;
    LARGE_INTEGER  WriteOperationCount;
    LARGE_INTEGER  OtherOperationCount;
    LARGE_INTEGER  ReadTransferCount;
    LARGE_INTEGER  WriteTransferCount;
    LARGE_INTEGER  OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

/////////////////////// Windows 95 /////////////////////////

#pragma pack(1)

#define VA_SHARED 0x8000000             // Undocumented flag to allocate shared memory in Win9x

// Kernel32 objects (WIN95)
#define WIN95_K32OBJ_SEMAPHORE            0x1
#define WIN95_K32OBJ_EVENT                0x2
#define WIN95_K32OBJ_MUTEX                0x3
#define WIN95_K32OBJ_CRITICAL_SECTION     0x4
#define WIN95_K32OBJ_PROCESS              0x5
#define WIN95_K32OBJ_THREAD               0x6
#define WIN95_K32OBJ_FILE                 0x7
#define WIN95_K32OBJ_CHANGE               0x8
#define WIN95_K32OBJ_CONSOLE              0x9
#define WIN95_K32OBJ_SCREEN_BUFFER        0xA
#define WIN95_K32OBJ_MEM_MAPPED_FILE      0xB
#define WIN95_K32OBJ_SERIAL               0xC
#define WIN95_K32OBJ_DEVICE_IOCTL         0xD
#define WIN95_K32OBJ_PIPE                 0xE
#define WIN95_K32OBJ_MAILSLOT             0xF
#define WIN95_K32OBJ_TOOLHELP_SNAPSHOT    0x10
#define WIN95_K32OBJ_SOCKET               0x11

// TIB flags
#define TIBF_WIN32                    0x00000001
#define TIBF_TRAP                     0x00000002

// Process Database flags (WIN95)
#define fDebugSingle                  0x00000001  // Set if process is being debugged
#define fCreateProcessEvent           0x00000002  // Set in debugged process after starting
#define fExitProcessEvent             0x00000004  // Might be set in debugged process at exit time
#define fWin16Process                 0x00000008  // 16-bit process
#define fDosProcess                   0x00000010  // DOS process
#define fConsoleProcess               0x00000020  // 32-bit console process
#define fFileApisAreOem               0x00000040  // SetFileAPIsToOEM
#define fNukeProcess                  0x00000080
#define fServiceProcess               0x00000100  // RegisterServiceProcess
#define fLoginScriptHack              0x00000800  // Might be a Novell network login process
#define fSendDllNotifications         0x00200000
#define fDebugEventPending            0x00400000  // e.g. stopped in debugger
#define fNearlyTerminating            0x00800000
#define fFaulted                      0x08000000
#define fTerminating                  0x10000000
#define fTerminated                   0x20000000
#define fInitError                    0x40000000
#define fSignaled                     0x80000000

// Thread Database flags (WIN95)
#define fCreateThreadEvent            0x00000001   // Set if thread is being debugged
#define fCancelExceptionAbort         0x00000002
#define fOnTempStack                  0x00000004
#define fGrowableStack                0x00000008
#define fDelaySingleStep              0x00000010
#define fOpenExeAsImmovableFile       0x00000020
#define fCreateSuspended              0x00000040   // CREATE_SUSPENDED flag to CreateProcess()
#define fStackOverflow                0x00000080
#define fNestedCleanAPCs              0x00000100
#define fWasOemNowAnsi                0x00000200   // ANSI/OEM file function
#define fOKToSetThreadOem             0x00000400   // ANSI/OEM file function

// TDBX flags (WIN95)
#define WAITEXBIT                     0x00000001
#define WAITACKBIT                    0x00000002
#define SUSPEND_APC_PENDING           0x00000004
#define SUSPEND_TERMINATED            0x00000008
#define BLOCKED_FOR_TERMINATION       0x00000010
#define EMULATE_NPX                   0x00000020
#define WIN32_NPX                     0x00000040
#define EXTENDED_HANDLES              0x00000080
#define FROZEN                        0x00000100
#define DONT_FREEZE                   0x00000200
#define DONT_UNFREEZE                 0x00000400
#define DONT_TRACE                    0x00000800
#define STOP_TRACING                  0x00001000
#define WAITING_FOR_CRST_SAFE         0x00002000
#define CRST_SAFE                     0x00004000
#define BLOCK_TERMINATE_APC           0x00040000

// Thread list
typedef struct {
    struct THREADLIST *pNext;
    struct THREADLIST *pPrev;
    DWORD  pTDB;
} THREADLIST, *PTHREADLIST;

// Environment Database
typedef struct _ENVIRONMENT_DATABASE {
    PSTR    pszEnvironment;             //00 Pointer to Process Environment
    DWORD   un1;                        //04 (always 0)
    PSTR    pszCmdLine;                 //08 Pointer to command line
    PSTR    pszCurrDirectory;           //0C Pointer to current directory
    LPSTARTUPINFOA pStartupInfo;        //10 Pointer to STARTUPINFOA struct
    HANDLE  hStdIn;                     //14 Standard Input handle
    HANDLE  hStdOut;                    //18 Standard Output handle
    HANDLE  hStdErr;                    //1C Standard Error handle
    DWORD   un2;                        //20 (always 1)
    DWORD   InheritConsole;             //24 Inherit console from parent
    DWORD   BreakType;                  //28 Handle console events (like CTRL+C)
    DWORD   BreakSem;                   //2C Pointer to K32OBJ_SEMAPHORE
    DWORD   BreakEvent;                 //30 Pointer to K32OBJ_EVENT
    DWORD   BreakThreadID;              //34 Pointer to K32OBJ_THREAD
    DWORD   BreakHandlers;              //38 Pointer to list of installed console control handlers
} EDB, *PEDB;

// Handle Table Entry
typedef struct _HANDLE_TABLE_ENTRY {
    DWORD  flags;                   // Valid flags depend on what type of object this is
    PVOID  pObject;                 // Pointer to the object that the handle refers to
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

// Handle Table
typedef struct _HANDLE_TABLE {
    DWORD cEntries;                 // Max number of handles in table
    HANDLE_TABLE_ENTRY array[1];    // An array (number is given by cEntries)
} HANDLE_TABLE, *PHANDLE_TABLE;

// MODREF
typedef struct _MODREF {
    struct MODREF*  pNextModRef;    //00 Pointer to next MODREF in list (EOL=NULL)
    DWORD  un1;                     //04 number of ?
    DWORD  un2;                     //08 Ring0 TCB ?
    DWORD  un3;                     //0C
    WORD   mteIndex;                //10 Index to global array of pointers to IMTEs
    WORD   un4;                     //12
    DWORD  un5;                     //14
    PVOID  ppdb;                    //18 Pointer to process database
    DWORD  un6;                     //1C
    DWORD  un7;                     //20
    DWORD  un8;                     //24
} MODREF, *PMODREF;

typedef struct _IMTE
{
    DWORD           un1;            // 00h
    PIMAGE_NT_HEADERS   pNTHdr;     // 04h
    DWORD           un2;            // 08h
    PSTR            pszFileName;    // 0Ch
    PSTR            pszModName;     // 10h
    WORD            cbFileName;     // 14h
    WORD            cbModName;      // 16h
    DWORD           un3;            // 18h
    DWORD           cSections;      // 1Ch
    DWORD           un5;            // 20h
    DWORD           baseAddress;    // 24h
    WORD            hModule16;      // 28h
    WORD            cUsage;         // 2Ah
    DWORD           un7;            // 2Ch
    PSTR            pszFileName2;   // 30h
    WORD            cbFileName2;    // 34h
    PSTR            pszModName2;    // 36h
    WORD            cbModName2;     // 3Ah
} IMTE, *PIMTE;

// Thread Information Block (FS:[0x18])
typedef struct _TIB95 {         // Size = 0x34
    PSEH    pvExcept;           // 00 Pointer to head of structured exception handling chain
    PVOID   pvStackUserTop;     // 04 Max. address for stack
    PVOID   pvStackUserBase;    // 08 Lowest page aligned addr. of stack
    WORD    pvTDB;              // 0C Ptr to win-16 task database
    WORD    pvThunksSS;         // 0E SS selector used for thunking to 16 bits
    DWORD   SelmanList;         // 10 Pointer to selector manager list
    PVOID   pvArbitrary;        // 14 Available for application use
    struct _TIB95 *pTIBSelf;    // 18 Linear address of TIB structure
    WORD    TIBFlags;           // 1C TIBF_WIN32 = 1, TIBF_TRAP = 2
    WORD    Win16MutexCount;    // 1E Win16Lock
    DWORD   DebugContext;       // 20 Pointer to debug context structure
    DWORD   pCurrentPriority;   // 24 Pointer to DWORD containing current priority level
    DWORD   pvQueue;            // 28 Message Queue selector
    PVOID*  pvTLSArray;         // 2C Thread Local Storage (TLS) array
    PVOID*  pProcess;           // 30 Pointer to owning process database (PDB)
} TIB95, *PTIB95;

// Process Database (FS:[0x30])
typedef struct _PDB95 {                 // Size = 0xC0 (from Kernel32)
    DWORD   Type;                       //00 KERNEL32 object type (K32OBJ_PROCESS = 5)
    DWORD   cReference;                 //04 Number of references to process
    DWORD   Unknown1;                   //08 (always 0)
    DWORD   pEvent;                     //0C Pointer to K32OBJ_EVENT (2)
    DWORD   TerminationStatus;          //10 Returned by GetExitCodeProcess()
    DWORD   Unknown2;                   //14 (always 0)
    DWORD   DefaultHeap;                //18 Address of the default process heap
    DWORD   MemoryContext;              //1C Pointer to the process's context (Returned by GetProcessHeap())
    DWORD   Flags;                      //20 Flags
    DWORD   pPSP;                       //24 Linear address of PSP ?
    WORD    PSPSelector;                //28 Selector for DOS PSP
    WORD    MTEIndex;                   //2A *4 + ModuleList = IMTE
    WORD    cThreads;                   //2C Number of threads belonging to this process
    WORD    cNotTermThreads;            //2E Number of threads for this process that haven't yet been terminated
    WORD    Unknown3;                   //30 (always 0)
    WORD    cRing0Threads;              //32 Number of ring 0 threads
    HANDLE  HeapHandle;                 //34 Heap to allocate handle tables out of (this seems to always be the KERNEL32 heap)
    HTASK   W16TDB;                     //38 Win16 Task Database selector
    DWORD   MemMapFiles;                //3C Pointer to memory mapped file list
    PEDB    pEDB;                       //40 Pointer to Environment Database
    PHANDLE_TABLE pHandleTable;         //44 Pointer to process handle table
    struct PDB95* ParentPDB;            //48 Parent process database
    PMODREF MODREFlist;                 //4C Pointer to module reference list
    DWORD   ThreadList;                 //50 Pointer to list of threads owned by this process
    DWORD   DebuggeeCB;                 //54 Debuggee Context block ?
    DWORD   LocalHeapFreeHead;          //58 Pointer to head of free list in process heap
    DWORD   InitialRing0ID;             //5C (always 0)
    CRITICAL_SECTION CriticalSection;   //60 Defined in winnt.h (len=0x18)
    DWORD   Unknow4[2];                 //78 (always 0)
    DWORD   pConsole;                   //80 Pointer to console object for process (K32OBJ_CONSOLE = 9)
    DWORD   tlsInUseBits1;              //84 Represents TLS status bits 0 - 31
    DWORD   tlsInUseBits2;              //88 Represents TLS status bits 32 - 63
    DWORD   ProcessDWORD;               //8C Retrieved by GetProcessDword()
    struct PDB95* ProcessGroup;         //90 Pointer to the master process (K32_OBJ_PROCESS = 5)
    DWORD   pExeMODREF;                 //94 Pointer to EXE's MODREF
    DWORD   TopExcFilter;               //98 Top Exception Filter
    DWORD   PriorityClass;              //9C Base scheduling priority for process (8 = NORMAL)
    DWORD   HeapList;                   //A0 Head of the list of process heaps
    DWORD   HeapHandleList;             //A4 Pointer to head of heap handle block list
    DWORD   HeapPointer;                //A8 Normally zero, but can pointer to a moveable handle block in the heap
    DWORD   pConsoleProvider;           //AC Zero or process that owns the console we're using (K32OBJ_CONSOLE)
    WORD    EnvironSelector;            //B0 Selector containing process environment
    WORD    ErrorMode;                  //B2 Value set by SetErrorMode()
    DWORD   pEventLoadFinished;         //B4 Pointer to event LoadFinished (K32OBJ_EVENT = 2)
    WORD    UTState;                    //B8
    DWORD   Unknown5[2];                //BA
} PDB95, *PPDB95;

// Thread Database Extension
typedef struct _TDBX95 {
    DWORD  ptdb;              // 00 TDB
    DWORD  ppdb;              // 04 PDB
    DWORD  ContextHandle;     // 08 R0 memory context
    DWORD  un1;               // 0C
    DWORD  TimeOutHandle;     // 10
    DWORD  WakeParam;         // 14
    DWORD  BlockHandle;       // 18 R0 semaphore on which thread will wait inside VWIN32
    DWORD  BlockState;        // 1C
    DWORD  SuspendCount;      // 20 Number of times SuspendThread() was called
    DWORD  SuspendHandle;     // 24
    DWORD  MustCompleteCount; // 28 Count of EnterMustComplete's minus LeaveMustComplete's
    DWORD  WaitExFlags;       // 2C Flags
    DWORD  SyncWaitCount;     // 30
    DWORD  QueuedSyncFuncs;   // 34
    DWORD  UserAPCList;       // 38
    DWORD  KernAPCList;       // 3C
    DWORD  pPMPSPSelector;    // 40 Pointer to protected mode PSP selector
    DWORD  BlockedOnID;       // 44
    DWORD  un2[7];            // 48
    DWORD  TraceRefData;      // 64
    DWORD  TraceCallBack;     // 68
    DWORD  TraceEventHandle;  // 6C
    WORD   TraceOutLastCS;    // 70
    WORD   K16TDB;            // 72 Win16 TDB selector
    WORD   K16PDB;            // 74 Win16 PSP selector
    WORD   DosPDBSeg;         // 76 Real mode segment value of PSP
    WORD   ExceptionCount;    // 78
} TDBX95, *PTDBX95;

// Thread Database (FS:[0x18] - 0x10)
typedef struct _TDB95 {                // Size = 0x1D4 (from Kernel32)
    DWORD      Type;                   // 00 Object type = K32OBJ_THREAD (6)
    DWORD      cReference;             // 04 Reference count for thread
    PPDB95     pProcess;               // 08 Pointer to PDB
    DWORD      pSomeEvent;             // 0C Pointer to K32OBJ_EVENT
    TIB95      tib;                    // 10-40 TIB
    DWORD      Flags;                  // 44 Flags
    DWORD      TerminationStatus;      // 48 Returned by GetExitCodeThread()
    WORD       TIBSelector;            // 4C TIB selector
    WORD       EmulatorSelector;       // 4E 80387 emulator state selector
    DWORD      cHandles;               // 50 (always 0)
    DWORD      WaitNodeList;           // 54 Pointer to event list
    DWORD      un4;                    // 58 (0 or 2)
    DWORD      Ring0Thread;            // 5C Pointer to ring0 THCB (Thread Control Block)
    TDBX95     *pTDBX;                 // 60 Pointer to TDBX
    DWORD      StackBase;              // 64 Lowest stack address
    DWORD      TerminationStack;       // 68 ESP for thread termination
    DWORD      EmulatorData;           // 6C Linear address for 80387 emulator data
    DWORD      GetLastErrorCode;       // 70 Value returned by GetLastErrorCode()
    DWORD      DebuggerCB;             // 74 Pointer do debugger data
    DWORD      DebuggerThread;         // 78 If thread is being debugged contains a non-NULL value
    PCONTEXT   ThreadContext;          // 7C Register context defined in WINNT.H
    DWORD      Except16List;           // 80 (always 0)
    DWORD      ThunkConnect;           // 84 (always 0)
    DWORD      NegStackBase;           // 88 StackBase + NegStackBase
    DWORD      CurrentSS;              // 8C 16-bit stack selector for thunking
    DWORD      SSTable;                // 90 Pointer to memory block with 16-bit stack info for thunking
    DWORD      ThunkSS16;              // 94 Selector for thunking
    DWORD      TLSArray[64];           // 98 TLS array
    DWORD      DeltaPriority;          // 198 Diference between priority of thread and priority class of the owning process
    DWORD      un5[7];                 // 19C
    DWORD      APISuspendCount;        // 1B8 Number of times SuspendThread() has been called
    DWORD      un[6];                  // 1BC

/*
    // The retail version breaks off somewhere around here.
    // All the remaining fields are most likely only in the debug version
    DWORD      un5[7];                 // 19C (always 0)
    DWORD      pCreateData16;          // 1B8 Pointer to struct with PProcessInfo and pStartupInfo (always 0)
    DWORD      APISuspendCount;        // 1BC Number of times SuspendThread() has been called
    DWORD      un6;                    // 1C0
    DWORD      WOWChain;               // 1C4 (always 0)
    WORD       wSSBig;                 // 1C8 32-bit stack selector (always 0)
    WORD       un7;                    // 1CA
    DWORD      lp16SwitchRec;          // 1CC
    DWORD      un8[6];                 // 1D0 (always 0)
    DWORD      pSomeCritSect1;         // 1E8 Pointer to K32OBJ_CRITICAL_SECTION
    DWORD      pWin16Mutex;            // 1EC Pointer to Win16Mutex in KRNL386.EXE
    DWORD      pWin32Mutex;            // 1F0 Pointer to Krn32Mutex in KERNEL32.DLL
    DWORD      pSomeCritSect2;         // 1F4 Pointer to K32OBJ_CRITICAL_SECTION
    DWORD      un9;                    // 1F8 (always 0)
    DWORD      ripString;              // 1FC
    DWORD      LastTlsSetValueEIP[64]; // 200 Parallel to TlsArray, contains EIP where TLS value was last set from
*/
} TDB95, *PTDB95;

/////////////////////// Windows 98 /////////////////////////

// Kernel32 objects (WIN98)
#define WIN98_K32OBJ_SEMAPHORE            0x1
#define WIN98_K32OBJ_EVENT                0x2
#define WIN98_K32OBJ_MUTEX                0x3
#define WIN98_K32OBJ_CRITICAL_SECTION     0x4
#define WIN98_K32OBJ_CHANGE               0x5
#define WIN98_K32OBJ_PROCESS              0x6
#define WIN98_K32OBJ_THREAD               0x7
#define WIN98_K32OBJ_FILE                 0x8
#define WIN98_K32OBJ_CONSOLE              0x9
#define WIN98_K32OBJ_SCREEN_BUFFER        0xA
#define WIN98_K32OBJ_MAILSLOT             0xB
#define WIN98_K32OBJ_SERIAL               0xC
#define WIN98_K32OBJ_MEM_MAPPED_FILE      0xD
#define WIN98_K32OBJ_PIPE                 0xE
#define WIN98_K32OBJ_DEVICE_IOCTL         0xF
#define WIN98_K32OBJ_TOOLHELP_SNAPSHOT    0x10
#define WIN98_K32OBJ_SOCKET               0x11

typedef struct _TDBX98 TDBX98;
typedef struct _PDB98  PDB98;

// Thread Information Block (FS:[0x18])
typedef struct _TIB98 {        // Size = 0x38
    PSEH    pvExcept;          // 00 Head of exception record list
    PVOID   pvStackUserTop;    // 04 Top of user stack
    PVOID   pvStackUserBase;   // 08 Base of user stack
    WORD    pvTDB;             // 0C Ptr to win-16 task database
    WORD    pvThunksSS;        // 0E SS selector used for thunking to 16 bits
    DWORD   SelmanList;        // 10 Pointer to selector manager list
    PVOID   pvArbitrary;       // 14 Available for application use
    struct _TIB98 *pTIBSelf;   // 18 Linear address of TIB structure
    WORD    TIBFlags;          // 1C TIBF_WIN32 = 1, TIBF_TRAP = 2
    WORD    Win16MutexCount;   // 1E Win16Lock
    DWORD   DebugContext;      // 20 Pointer to debug context structure
    DWORD   pCurrentPriority;  // 24 Pointer to DWORD containing current priority level
    DWORD   pvQueue;           // 28 Message Queue selector
    PVOID   *pvTLSArray;       // 2C Thread Local Storage (TLS) array
    PVOID   *pProcess;         // 30 Pointer to owning process database (PDB)
    DWORD   Unknown;           // 34 Pointer to ???
} TIB98, *PTIB98;

// Thread database (FS:[0x18] - 0x8)
typedef struct _TDB98 {        // Size = 0x228 (from Kernel32)
    WORD    Type;              // 00 K32 object type
    WORD    cReference;        // 02 Reference count
    DWORD   pSomeEvent;        // 04 K32 event object used when someone waits on the thread object
    TIB98   tib;               // 08 Thread information block (TIB)
    DWORD   Unknown;           // 40
    DWORD   Flags;             // 44 Flags
    DWORD   TerminationStatus; // 48 Exit code
    WORD    TIBSelector;       // 4C Selector used in FS to point to TIB
    WORD    EmulatorSelector;  // 4E Memory block for saving x87 state
    DWORD   cHandles;          // 50 Handle count
    DWORD   Ring0Thread;       // 54 R0 thread control block (TCB)
    TDBX98  *pTDBX;            // 58 R0 thread database extension (TDBX)
    DWORD   un1[109];          // 5C
    DWORD   APISuspendCount;   // 210 Count of SuspendThread's minus ResumeThread's
} TDB98, *PTDB98;

// Thread database extension
typedef struct _TDBX98 {
    DWORD  un0;                // 00
    TDB98  *ptdb;              // 04 R3 thread database
    PDB98  *ppdb;              // 08 R3 process database
    DWORD  ContextHandle;      // 0C R0 memory context
    DWORD  Ring0Thread;        // 10 R0 thread control block [TCB *]
    DWORD  WaitNodeList;       // 14 Anchor of things we're waiting on  [WAITNODE *]
    DWORD  WaitFlags;          // 18 Blocking flags
    DWORD  un1;                // 1C
    DWORD  TimeOutHandle;      // 20
    DWORD  WakeParam;          // 24
    DWORD  BlockHandle;        // 28 R0 semaphore on which thread will wait inside VWIN32
    DWORD  BlockState;         // 2C
    DWORD  SuspendCount;       // 30
    DWORD  SuspendHandle;      // 34
    DWORD  MustCompleteCount;  // 38 Count of EnterMustComplete's minus LeaveMustComplete's
    DWORD  WaitExFlags;        // 3C Flags
    DWORD  SyncWaitCount;      // 40
    DWORD  QueuedSyncFuncs;    // 44
    DWORD  UserAPCList;        // 48
    DWORD  KernAPCList;        // 4C
    DWORD  pPMPSPSelector;     // 50
    DWORD  BlockedOnID;        // 54
} TDBX98, *PTDBX98;

// Process Database (FS:0x30])
typedef struct _PDB98 {                 // Size = 0xC4 (from Kernel32)
    BYTE    Type;                       // 00 Kernel object type = K32OBJ_PROCESS (6)
    BYTE    Unknown_A;                  // 01 (align ?)
    WORD    cReference;                 // 02 Number of references to process
    DWORD   Unknown_B;                  // 04 Pointer to ???
    DWORD   Unknown1;                   // 08 (zero)
    DWORD   pEvent;                     // 0C Event for process waiting
    DWORD   TerminationStatus;          // 10 GetExitCodeProcess
    DWORD   Unknown2;                   // 14 May be used for private purposes
    DWORD   DefaultHeap;                // 18 GetProcessHeap
    DWORD   MemoryContext;              // 1C Pointer to process context
    DWORD   Flags;                      // 20 Flags
    DWORD   pPSP;                       // 24 Linear address of DOS PSP
    WORD    PSPSelector;                // 28 Selector to DOS PSP
    WORD    MTEIndex;                   // 2A Index into global module table
    WORD    cThreads;                   // 2C Threads.ItemCount
    WORD    cNotTermThreads;            // 2E Threads.ItemCount
    WORD    Unknown3;                   // 30 (zero)
    WORD    cRing0Threads;              // 32 Normally Threads.ItemCount (except kernel32)
    HANDLE  HeapHandle;                 // 34 Kernel32 shared heap
    DWORD   w16TDB;                     // 38 Win16 task database selector
    DWORD   MemMappedFiles;             // 3C List of memory mapped files
    PEDB    pEDB;                       // 40 Pointer to Environment Database
    PHANDLE_TABLE pHandleTable;         // 44 Pointer to Handle Table
    struct PDB98* ParentPDB;            // 48 Pointer to parent process (PDB)
    PMODREF MODREFList;                 // 4C Pointer to list of modules
    DWORD   ThreadList;                 // 50 Pointer to list of threads
    DWORD   DebuggeeCB;                 // 54 Debuggee context block
    DWORD   LocalHeapFreeHead;          // 58 Free list for process default heap
    DWORD   InitialRing0ID;             // 5C Meaning unknown
    CRITICAL_SECTION CriticalSection;   // 60 For synchronizing threads
    DWORD   Unknown4[3];                // 78
    DWORD   pConsole;                   // 84 Output console
    DWORD   tlsInUseBits1;              // 88 Status of TLS indexes  0 - 31
    DWORD   tlsInUseBits2;              // 8C Status of TLS indexes 32 - 63
    DWORD   ProcessDWORD;               // 90 Undocumented API GetProcessDword, meaning unknown
    struct PDB98* ProcessGroup;         // 94 Master process PDB (in debugging)
    DWORD   pExeMODREF;                 // 98 Points to exe's module structure
    DWORD   TopExcFilter;               // 9C SetUnhandledExceptionFilter
    DWORD   PriorityClass;              // A0 PriorityClass (8 = NORMAL)
    DWORD   HeapList;                   // A4 List of heaps
    DWORD   HeapHandleList;             // A8 List of moveable memory blocks
    DWORD   HeapPointer;                // AC Pointer to one moveable memory block, meaning unknown
    DWORD   pConsoleProvider;           // B0 Console for DOS apps
    WORD    EnvironSelector;            // B4 Environment database selector
    WORD    ErrorMode;                  // B6 SetErrorMode
    DWORD   pEventLoadFinished;         // B8 Signaled when the process has finished loading
    WORD    UTState;                    // BC Universal thunking, meaning unknown
    WORD    Unknown5;                   // BE (zero)
    DWORD   Unknown6;                   // C0
} PDB98, *PPDB98;

/////////////////////// Windows Me /////////////////////////

typedef TIB98   TIBME;
typedef TIBME   *PTIBME;

typedef struct _TDBME {        // Size = 0x228 (from Kernel32)
    WORD    Type;              // 00 K32 object type
    WORD    cReference;        // 02 Reference count
    DWORD   pSomeEvent;        // 04 K32 event object used when someone waits on the thread object
    TIB98   tib;               // 08 Thread information block (TIB)
    DWORD   Unknown;           // 40
    DWORD   Unknown2;          // 44
    WORD    TIBSelector;       // 46 Selector used in FS to point to TIB
    DWORD   TerminationStatus; // 48 Exit code
    DWORD   Flags;             // 4C Flags
    DWORD   cHandles;          // 50 Handle count
    DWORD   Ring0Thread;       // 54 R0 thread control block (TCB)
    DWORD   Unknown3;          // 58 Selector for ???
    DWORD   un1[109];          // 5C
    DWORD   APISuspendCount;   // 210 Count of SuspendThread's minus ResumeThread's
} TDBME, *PTDBME;

typedef struct _PDBME {                 // Size = 0xC4 (from Kernel32)
    BYTE    Type;                       // 00 Kernel object type = K32OBJ_PROCESS (6)
    BYTE    Unknown_A;                  // 01 (align ?)
    WORD    cReference;                 // 02 Number of references to process
    DWORD   Unknown_B;                  // 04 Pointer to ???
    DWORD   Unknown1;                   // 08 (zero)
    DWORD   pEvent;                     // 0C Event for process waiting
    DWORD   TerminationStatus;          // 10 GetExitCodeProcess
    DWORD   Unknown2;                   // 14 May be used for private purposes
    DWORD   DefaultHeap;                // 18 GetProcessHeap
    DWORD   MemoryContext;              // 1C Pointer to process context
    DWORD   Flags;                      // 20 Flags
    DWORD   pPSP;                       // 24 Linear address of DOS PSP
    WORD    PSPSelector;                // 28 Selector to DOS PSP
    WORD    MTEIndex;                   // 2A Index into global module table
    WORD    cThreads;                   // 2C Threads.ItemCount
    WORD    cNotTermThreads;            // 2E Threads.ItemCount
    WORD    Unknown3;                   // 30 (zero)
    WORD    cRing0Threads;              // 32 Normally Threads.ItemCount (except kernel32)
    HANDLE  HeapHandle;                 // 34 Kernel32 shared heap
    DWORD   w16TDB;                     // 38 Win16 task database selector
    DWORD   MemMappedFiles;             // 3C List of memory mapped files
    PEDB    pEDB;                       // 40 Pointer to Environment Database
    PHANDLE_TABLE pHandleTable;         // 44 Pointer to Handle Table
    struct PDB98* ParentPDB;            // 48 Pointer to parent process (PDB)
    PMODREF MODREFList;                 // 4C Pointer to list of modules
    DWORD   ThreadList;                 // 50 Pointer to list of threads
    DWORD   DebuggeeCB;                 // 54 Debuggee context block
    DWORD   LocalHeapFreeHead;          // 58 Free list for process default heap
    DWORD   InitialRing0ID;             // 5C Meaning unknown
    CRITICAL_SECTION CriticalSection;   // 60 For synchronizing threads
    DWORD   Unknown4[2];                // 78
    DWORD   pConsole;                   // 80 Output console
    DWORD   tlsInUseBits1;              // 84 Status of TLS indexes  0 - 31
    DWORD   tlsInUseBits2;              // 88 Status of TLS indexes 32 - 63
    DWORD   ProcessDWORD;               // 8C Undocumented API GetProcessDword, meaning unknown
    DWORD   Unknown_C;                  // 90 Unknown
    struct PDB98* ProcessGroup;         // 94 Master process PDB (in debugging)
    DWORD   pExeMODREF;                 // 98 Points to exe's module structure
    DWORD   TopExcFilter;               // 9C SetUnhandledExceptionFilter
    DWORD   PriorityClass;              // A0 PriorityClass (8 = NORMAL)
    DWORD   HeapList;                   // A4 List of heaps
    DWORD   HeapHandleList;             // A8 List of moveable memory blocks
    DWORD   HeapPointer;                // AC Pointer to one moveable memory block, meaning unknown
    DWORD   pConsoleProvider;           // B0 Console for DOS apps
    WORD    EnvironSelector;            // B4 Environment database selector
    WORD    ErrorMode;                  // B6 SetErrorMode
    DWORD   pEventLoadFinished;         // B8 Signaled when the process has finished loading
    WORD    UTState;                    // BC Universal thunking, meaning unknown
    WORD    Unknown5;                   // BE (zero)
    DWORD   Unknown6;                   // C0
} PDBME, *PPDBME;

#pragma pack()

#endif // __STRUCT_H__
