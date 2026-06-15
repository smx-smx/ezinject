#ifndef __EZINJECT_CTX_PLATFORM_WINDOWS_H
#define __EZINJECT_CTX_PLATFORM_WINDOWS_H

struct ctx_platform {
	int wait_call_seq;
	DEBUG_EVENT ev;
	HANDLE hProc;
	HANDLE hThread;
	DWORD target_tid;
	uintptr_t r_ezstate_addr;
	uint8_t *saved_sc_data;
	ssize_t saved_sc_size;
	int force_mmap_syscall;
	ez_addr virtual_alloc;
	ez_addr virtual_free;
	ez_addr suspend_thread;
	ez_addr get_current_thread;
	ez_addr create_file;
	ez_addr write_file;
	ez_addr close_handle;
	ez_addr nt_register_dll_noti;
	ez_addr nt_unregister_dll_noti;
};

#endif
