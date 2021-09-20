#ifndef __EZINJECT_INJCODE_H
#define __EZINJECT_INJCODE_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <pthread.h>

#include "config.h"

#ifdef EZ_TARGET_WINDOWS
#include <windows.h>
#include <ntdef.h>
#include <winternl.h>
#endif

#define SC_MAX_ARGS 8
#include "ezinject_common.h"

#define EZAPI intptr_t

#ifdef EZ_TARGET_DARWIN
#define SECTION(X) __attribute__((section("__DATA,__" X)))
#define SECTION_START(X) __asm("section$start$__DATA$__" X)
#define SECTION_END(X) __asm("section$end$__DATA$__" X)
#else
#define SECTION(X) __attribute__((section(X)))
#define SECTION_START(X)
#define SECTION_END(X)
#endif

#define PLAPI SECTION("payload")
#define SCAPI SECTION("syscall")

#define SIZEOF_BR(br) (sizeof(br) + (br).dyn_size)

// temporary stack size
#define PL_STACK_SIZE 1024 * 1024 * 4

#ifdef EZ_TARGET_DARWIN
#define LABEL_PREFIX "_"
#else
#define LABEL_PREFIX
#endif
#define EMIT_LABEL(name) \
	asm volatile( \
		".globl "LABEL_PREFIX name"\n" \
		LABEL_PREFIX name":\n" \
	)


#define INLINE static inline __attribute__((always_inline))

#ifdef HAVE_DL_LOAD_SHARED_LIBRARY
#include <elf.h>

#define ElfW(type)	_ElfW (Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e,w,t)	_ElfW_1 (e, w, _##t)
#define _ElfW_1(e,w,t)	e##w##t
#define DL_LOADADDR_TYPE ElfW(Addr)
#include <link.h>		/* Defines __ELF_NATIVE_CLASS.  */

#ifndef UCLIBC_OLD
struct r_scope_elem {
	void **r_list; /* Array of maps for the scope.  */
	unsigned int r_nlist;        /* Number of entries in the scope.  */
	void *next;
};
#endif

struct init_fini {
    void **init_fini;
    unsigned long nlist; /* Number of entries in init_fini */
};

struct dyn_elf {
  void * dyn;
  void * next_handle;  /* Used by dlopen et al. */
  struct init_fini init_fini;
  void * next;
  void * prev;
};

struct elf_resolve_hdr {
	/* These entries must be in this order to be compatible with the interface used
		by gdb to obtain the list of symbols. */
	DL_LOADADDR_TYPE loadaddr;	/* Base address shared object is loaded at.  */
	char *libname;		/* Absolute file name object was found in.  */
	ElfW(Dyn) *dynamic_addr;	/* Dynamic section of the shared object.  */
	struct elf_resolve_hdr *next;
	struct elf_resolve_hdr *prev;
	/* Nothing after this address is used by gdb. */
};
#endif

struct injcode_user {
	uint8_t persist;
};

struct injcode_call;
struct injcode_sc_wrapper {
	// pointer to the actual function to call
	intptr_t (*target)(volatile struct injcode_call *args);
};

struct injcode_trampoline {
	uintptr_t fn_arg;
	uintptr_t fn_addr;
};

struct injcode_call {
#ifdef EZ_TARGET_POSIX
	long (*libc_syscall)(long number, ...);
#endif
	int argc;
	intptr_t result;
	intptr_t result2;
	uintptr_t argv[SC_MAX_ARGS];
	struct injcode_sc_wrapper wrapper;
	/**
	 * since we are skipping the prologue of the trampoline
	 * we're not doing a proper stack allocation
	 * this means that calling conventions like cdecl will overwrite a part of this struct
	 * when pushing
	 * so we have to reserve enough stack for trampoline here
	 */
	uint8_t scratch[256];
	struct injcode_trampoline trampoline;
};

/**
 * fn_args points to the remote injcode_call
 * get the remote address to the given field
 */
#define RCALL_FIELD_ADDR(rcall, field) \
	(((rcall)->trampoline.fn_arg) + offsetof(struct injcode_call, field))

struct injcode_bearing
{
	size_t mapping_size;

	int pl_debug;
	off_t stack_offset;
	pthread_t user_tid;
#ifdef EZ_TARGET_WINDOWS
	HANDLE hThread;
	HANDLE hEvent;
#endif
	void *userlib;

#if defined(HAVE_DL_LOAD_SHARED_LIBRARY)
	void *(*libc_dlopen)(unsigned rflags, struct dyn_elf **rpnt,
		void *tpnt, char *full_libname, int trace_loaded_objects);
	struct dyn_elf **uclibc_sym_tables;
	#ifdef UCLIBC_OLD
	int (*uclibc_dl_fixup)(struct dyn_elf *rpnt, int now_flag);
	#else
	int (*uclibc_dl_fixup)(struct dyn_elf *rpnt, struct r_scope_elem *scope, int now_flag);
	#endif
	#ifdef EZ_ARCH_MIPS
	void (*uclibc_mips_got_reloc)(struct elf_resolve_hdr *tpnt, int lazy);
	#endif
	struct elf_resolve_hdr **uclibc_loaded_modules;
#elif defined(HAVE_LIBDL_IN_LIBC) \
|| defined(HAVE_LIBC_DLOPEN_MODE) \
|| defined(EZ_TARGET_ANDROID) \
|| defined(EZ_TARGET_DARWIN)
	void *(*libc_dlopen)(const char *name, int mode);
#elif defined(EZ_TARGET_WINDOWS)
	// LdrLoadDll
	NTSTATUS NTAPI (*libc_dlopen)(
		PWSTR SearchPath,
		PULONG DllCharacteristics,
		PUNICODE_STRING DllName,
		PVOID *BaseAddress
	);
	NTSTATUS NTAPI (*NtQueryInformationProcess)(
		HANDLE           ProcessHandle,
		PROCESSINFOCLASS ProcessInformationClass,
		PVOID            ProcessInformation,
		ULONG            ProcessInformationLength,
		PULONG           ReturnLength
	);
	PPEB NTAPI (*RtlGetCurrentPeb)();
	NTSTATUS NTAPI (*NtWriteFile)(
		HANDLE           FileHandle,
		HANDLE           Event,
		PIO_APC_ROUTINE  ApcRoutine,
		PVOID            ApcContext,
		PIO_STATUS_BLOCK IoStatusBlock,
		PVOID            Buffer,
		ULONG            Length,
		PLARGE_INTEGER   ByteOffset,
		PULONG           Key
	);
#endif
	off_t dlopen_offset;
	off_t dlclose_offset;
	off_t dlsym_offset;
	// libdl base address, if already loaded
	void *libdl_handle;
	long (*libc_syscall)(long number, ...);
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	uint8_t loaded_signal;
	struct injcode_user user;
	int num_strings;
	off_t argv_offset;
	int argc;
	int dyn_size;
	char *argv[];
};

enum userlib_return_action {
	userlib_unload = 0,
	userlib_persist = 1
};


#ifdef EZ_TARGET_WINDOWS
typedef struct _CURDIR {
     UNICODE_STRING DosPath;
     PVOID Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
     WORD Flags;
     WORD Length;
     ULONG TimeStamp;
     STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct {
     ULONG MaximumLength;
     ULONG Length;
     ULONG Flags;
     ULONG DebugFlags;
     PVOID ConsoleHandle;
     ULONG ConsoleFlags;
     PVOID StandardInput;
     PVOID StandardOutput;
     PVOID StandardError;
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
     RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
     ULONG EnvironmentSize;
} INT_RTL_USER_PROCESS_PARAMETERS, *PINT_RTL_USER_PROCESS_PARAMETERS;
#endif

#ifdef EZ_TARGET_POSIX
extern intptr_t SCAPI injected_sc0(volatile struct injcode_call *sc);
extern intptr_t SCAPI injected_sc1(volatile struct injcode_call *sc);
extern intptr_t SCAPI injected_sc2(volatile struct injcode_call *sc);
extern intptr_t SCAPI injected_sc3(volatile struct injcode_call *sc);
extern intptr_t SCAPI injected_sc4(volatile struct injcode_call *sc);
extern intptr_t SCAPI injected_sc5(volatile struct injcode_call *sc);
extern intptr_t SCAPI injected_sc6(volatile struct injcode_call *sc);
#endif

void SCAPI injected_sc_wrapper(volatile struct injcode_call *args);

extern void PLAPI trampoline();
extern void trampoline_entry();
extern void trampoline_exit();

extern intptr_t injected_fn(struct injcode_call *sc);

extern uint8_t __start_payload SECTION_START("payload");
extern uint8_t __stop_payload SECTION_END("payload");
extern uint8_t __start_syscall SECTION_START("syscall");
extern uint8_t __stop_syscall SECTION_END("syscall");

#define INJ_ERR_LIBDL 1
#define INJ_ERR_LIBPTHREAD 2
#define INJ_ERR_API 3
#define INJ_ERR_DLOPEN 4
#define INJ_ERR_WAIT 5

#endif
