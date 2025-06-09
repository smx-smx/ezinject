/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#ifndef __EZINJECT_INJCODE_H
#define __EZINJECT_INJCODE_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <pthread.h>

#include "config.h"
#include "ezinject_compat.h"
#include "ezinject_arch.h"

#ifdef EZ_ARCH_HPPA
#define CALL_FPTR(x, ...) (((typeof(x.fptr))((x).self))(__VA_ARGS__))
#else
#define CALL_FPTR(x, ...) ((x).fptr(__VA_ARGS__))
#endif

#ifdef EZ_TARGET_WINDOWS
#include "os/windows/InjLib/Struct.h"
/*
#include <windows.h>
#include <ntdef.h>
#include <winternl.h>
*/
#endif

#ifdef EZ_TARGET_DARWIN
#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/thread_act.h>
#endif

#define SC_MAX_ARGS 8
#include "ezinject_common.h"

#define EZAPI intptr_t

#define PLAPI SECTION("payload")
#define SCAPI SECTION("syscall")

#define SIZEOF_BR(br) (sizeof(br) + (br).dyn_total_size)

// temporary stack size
#define PL_STACK_SIZE 1024 * 1024 * 2

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
	bool persist;
};

struct injcode_call;
struct injcode_sc_wrapper {
	struct {
		// pointer to the actual function to call
		intptr_t (*fptr)(volatile struct injcode_call *args);
		void *got;
		void *self;
	} target;
};

/**
 * the trampoline parameters
 * these are pushed at the top of the stack
 * and will be POP'd by the trampoline
 **/
struct injcode_trampoline {
	// first element consumed by GROW-DOWN SP
	uintptr_t fn_addr;
#ifdef EZ_ARCH_HPPA
	uintptr_t fn_got;
	// points to fn_addr
	uintptr_t fn_self;
#endif
	uintptr_t fn_arg;
	// first element consumed by GROW-UP SP
};

struct injcode_bearing;
struct injcode_ctx;

struct injcode_plapi {
	struct {
		void *(*fptr)(struct injcode_ctx *ctx, void *s, int c, size_t n);
		void *got;
		void *self;
	} inj_memset;
	struct {
		void (*fptr)(struct injcode_ctx *ctx, const char *str);
		void *got;
		void *self;
	} inj_puts;
	struct {
		void (*fptr)(struct injcode_ctx *ctx, char ch);
		void *got;
		void *self;
	} inj_dchar;
	struct {
		void (*fptr)(struct injcode_ctx *ctx, void *ptr);
		void *got;
		void *self;
	} inj_dbgptr;
	struct {
		intptr_t (*fptr)(struct injcode_ctx *ctx, enum ezinj_str_id str_id, void *handle, void **sym);
		void *got;
		void *self;
	} inj_fetchsym;
};

#define EZST1 0x455A5331 // signaled
// magic to mark PL syscall (used as syscall number)
#define EZBR1 0x455A4252
#define EZSC1 0x455A5343
#define EZCX1 0x455A4358

/**
 *
 * this structure is pushed on the stack
 * within the target process
 **/
struct injcode_call {
	uintptr_t magic; //EZSC1

#ifdef EZ_TARGET_POSIX
	struct {
		long (*fptr)(long number, ...);
		void *got;
		void *self;
	} libc_syscall;
#endif
#ifdef EZ_TARGET_LINUX
	struct {
		void *(*fptr)(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset);
		void *got;
		void *self;
	} libc_mmap;
	struct {
		int (*fptr)(const char *pathname, int flags, ...);
		void *got;
		void *self;
	} libc_open;
	struct {
		ssize_t (*fptr)(int fd, void *buf, size_t count);
		void *got;
		void *self;
	} libc_read;
#endif
#ifdef EZ_TARGET_WINDOWS
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
#endif

	uintptr_t ezstate;

	/** PLAPI **/
	struct injcode_plapi plapi;

	int argc;
	intptr_t result;
	uintptr_t argv[SC_MAX_ARGS];

	/**
	 * syscall wrapper parameters
	 **/
	struct injcode_sc_wrapper wrapper;

	/**
	 * this field acts as the stack for the entry point (trampoline)
	 */
	uint8_t entry_stack[512];

	/**
	 * trampoline parameters
	 * these *MUST* be at the bottom of the struct
	 * because this structure will be pushed on the stack
	 **/
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
	uintptr_t magic; //EZBR1
	
	struct {
		struct injcode_sc_wrapper wrapper;
	} entry;
	
	ssize_t mapping_size;

	int stbl_relocated;
	bool pl_debug;
	off_t stack_offset;
	pthread_t user_tid;
#ifdef EZ_TARGET_WINDOWS
	HANDLE hThread;
	HANDLE hEvent;
#endif
	void *userlib;

#ifdef EZ_TARGET_DARWIN
	thread_act_t mach_thread;
#endif

#if defined(EZ_TARGET_DARWIN)
	pthread_t tid;

	int (*pthread_create)(pthread_t *restrict thread,
		const pthread_attr_t *restrict attr,
		typeof(void *(void *)) *start_routine,
		void *restrict arg);
	int (*pthread_join)(pthread_t thread, void **value_ptr);
	int (*pthread_create_from_mach_thread)(
		pthread_t *thread,
		const pthread_attr_t *attr,
		void *(*start_routine)(void *), void *arg);
	pthread_t (*pthread_self)(void);
	int (*pthread_detach)(pthread_t thread);
	kern_return_t (*thread_terminate)(thread_act_t target_act);
	kern_return_t (*mach_port_allocate)
		(ipc_space_t        task,
		mach_port_right_t   right,
		mach_port_name_t    *name);
	thread_act_t (*mach_thread_self)(void);
	mach_port_t  (*task_self_trap)(void);
#endif

// uclibc
#if defined(HAVE_DL_LOAD_SHARED_LIBRARY)
	struct {
		void *(*fptr)(unsigned rflags, struct dyn_elf **rpnt,
			void *tpnt, char *full_libname, int trace_loaded_objects);
		void *got;
		void *self;
	} libc_dlopen;
	struct dyn_elf **uclibc_sym_tables;
	#ifdef UCLIBC_OLD
	struct {
		int (*fptr)(struct dyn_elf *rpnt, int now_flag);
		void *got;
		void *self;
	} uclibc_dl_fixup;
	#else
	struct {
		int (*fptr)(struct dyn_elf *rpnt, struct r_scope_elem *scope, int now_flag);
		void *got;
		void *self;
	} uclibc_dl_fixup;
	#endif
	#ifdef EZ_ARCH_MIPS
	struct {
		void (*fptr)(struct elf_resolve_hdr *tpnt, int lazy);
	} uclibc_mips_got_reloc;
	#endif
	struct elf_resolve_hdr **uclibc_loaded_modules;
// glibc
#elif defined(HAVE_LIBDL_IN_LIBC) \
|| defined(HAVE_LIBC_DLOPEN_MODE) \
|| defined(EZ_TARGET_ANDROID) \
|| defined(EZ_TARGET_DARWIN)
	struct {
		void *(*fptr)(const char *name, int mode);
		void *got;
		void *self;
	} libc_dlopen;
// old glibc
#elif defined(HAVE_LIBC_DL_OPEN)
	struct {
		void *(*fptr)(const char *name, int mode, void *caller);
		void *got;
		void *self;
	} libc_dlopen;
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
	WINBOOL (*CloseHandle)(
		HANDLE hObject
	);
	NTSTATUS NTAPI (*LdrRegisterDllNotification)(
  		ULONG   Flags,
		PVOID	NotificationFunction,
		PVOID   Context,
		PVOID   *Cookie
	);
	NTSTATUS NTAPI (*LdrUnregisterDllNotification)(
  		PVOID Cookie
	);
	WINBOOL WINAPI (*AllocConsole)(void);
	uintptr_t ntdll_base;
	uintptr_t kernel32_base;
#endif
	off_t dlopen_offset;
	off_t dlclose_offset;
	off_t dlsym_offset;
	// libdl base address, if already loaded
	void *libdl_handle;
	void *libc_got;
	void *libdl_got;
	struct {
		long (*fptr)(long number, ...);
		void *got;
		void *self;
	} libc_syscall;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	uint8_t loaded_signal;
	struct injcode_user user;
	unsigned num_strings;
	int thread_exit_code;
#ifdef EZ_TARGET_LINUX
	off_t pl_filename_offset;
#endif
	size_t dyn_total_size;
	int argc;
	char *argv[];
};

enum userlib_return_action {
	userlib_unload = 0,
	userlib_persist = 1
};


#ifdef EZ_TARGET_WINDOWS
/*
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
*/
#endif

extern void SCAPI injected_sc_trap(void);
extern void injected_sc_trap_start();
extern void injected_sc_trap_stop();

#ifdef EZ_TARGET_POSIX
extern intptr_t SCAPI injected_sc0(volatile struct injcode_call *sc);
extern intptr_t SCAPI injected_sc1(volatile struct injcode_call *sc);
extern intptr_t SCAPI injected_sc2(volatile struct injcode_call *sc);
extern intptr_t SCAPI injected_sc3(volatile struct injcode_call *sc);
extern intptr_t SCAPI injected_sc4(volatile struct injcode_call *sc);
extern intptr_t SCAPI injected_sc5(volatile struct injcode_call *sc);
extern intptr_t SCAPI injected_sc6(volatile struct injcode_call *sc);
#endif

#ifdef EZ_TARGET_LINUX
extern intptr_t SCAPI injected_mmap(volatile struct injcode_call *sc);
extern intptr_t SCAPI injected_open(volatile struct injcode_call *sc);
extern intptr_t SCAPI injected_read(volatile struct injcode_call *sc);
#endif

#ifdef EZ_TARGET_WINDOWS
intptr_t SCAPI injected_virtual_alloc(volatile struct injcode_call *sc);
intptr_t SCAPI injected_virtual_free(volatile struct injcode_call *sc);
#endif

void SCAPI injected_sc_wrapper(volatile struct injcode_call *args);
void PLAPI injected_pl_wrapper(volatile struct injcode_call *args);

extern void PLAPI trampoline();
extern void trampoline_entry();
extern void trampoline_exit();

extern intptr_t injected_fn(void *arg);

/** plapi **/
extern void *inj_memset(struct injcode_ctx *ctx, void *s, int c, size_t n);
extern void inj_puts(struct injcode_ctx *ctx, char *str);
extern void inj_dchar(struct injcode_ctx *ctx, char ch);
extern void inj_dbgptr(struct injcode_ctx *ctx, void *ptr);
extern intptr_t inj_fetchsym(struct injcode_ctx *ctx, enum ezinj_str_id str_id, void *handle, void **sym);

extern uint8_t __start_payload SECTION_START("payload");
extern uint8_t __stop_payload SECTION_END("payload");
extern uint8_t __start_syscall SECTION_START("syscall");
extern uint8_t __stop_syscall SECTION_END("syscall");

#define INJ_ERR_LIBDL 1
#define INJ_ERR_LIBPTHREAD 2
#define INJ_ERR_API 3
#define INJ_ERR_DLOPEN 4
#define INJ_ERR_WAIT 5
#define INJ_ERR_DARWIN_THREAD 6

#endif
