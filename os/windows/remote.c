/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <windows.h>
#include <debugapi.h>
#include <sys/types.h>
#include <tlhelp32.h>

#include "ezinject.h"
#include "log.h"

static EZAPI _grant_debug_privileges(){
	HANDLE token = NULL;
	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token)){
		PERROR("OpenProcessToken");
		return -1;
	}

	intptr_t rc = -1;

	do {
		LUID luid;
		if(!LookupPrivilegeValue(NULL, TEXT("SeDebugPrivilege"), &luid)){
			PERROR("LookupPrivilegeValue");
			break;
		}

		TOKEN_PRIVILEGES tp = {
			.PrivilegeCount = 1,
			.Privileges[0].Luid = luid,
			.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
		};

		if(!AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL)){
			PERROR("AdjustTokenPrivileges");
			break;
		}
		rc = 0;
	} while(0);

	if(token != NULL && token != INVALID_HANDLE_VALUE){
		CloseHandle(token);
	}
	return rc;
}

EZAPI remote_attach(struct ezinj_ctx *ctx){
	if(_grant_debug_privileges() < 0){
		ERR("_grant_debug_privileges failed");
		return -1;
	}

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, ctx->target);
	if(hProc == NULL || hProc == INVALID_HANDLE_VALUE){
		PERROR("OpenProcess failed");
		return -1;
	}
	ctx->hProc = hProc;
	if(remote_suspend(ctx) != 0){
		ERR("remote_suspend failed");
		return -1;
	}
	if(DebugSetProcessKillOnExit(FALSE) == FALSE){
		PERROR("DebugSetProcessKillOnExit failed");
		return -1;
	}
	return 0;
}

EZAPI remote_suspend(struct ezinj_ctx *ctx){
	if(DebugActiveProcess(ctx->target) == FALSE){
		PERROR("DebugActiveProcess failed");
		return -1;
	}
	return 0;
}

EZAPI remote_continue(struct ezinj_ctx *ctx, int signal){
	UNUSED(signal);

	DBG("Resuming %lu %lu", ctx->ev.dwProcessId, ctx->ev.dwThreadId);
	//ctx->hThread = INVALID_HANDLE_VALUE
	if(ContinueDebugEvent(ctx->ev.dwProcessId, ctx->ev.dwThreadId, DBG_EXCEPTION_HANDLED) == FALSE){
		return -1;
	}
	return 0;
}

EZAPI remote_step(struct ezinj_ctx *ctx, int signal){
	return -1;
}

EZAPI remote_detach(struct ezinj_ctx *ctx){
	// we need to dispatch the last debug event first
	remote_continue(ctx, 0);

	if(DebugActiveProcessStop(ctx->target) == FALSE){
		return -1;
	}
	return 0;
}

EZAPI remote_read(struct ezinj_ctx *ctx, void *dest, uintptr_t source, size_t size){
	size_t read = 0;
	ReadProcessMemory(ctx->hProc, (LPVOID)source, dest, size, &read);
	return read;
}

EZAPI remote_write(struct ezinj_ctx *ctx, uintptr_t dest, void *source, size_t size){
	size_t written = 0;
	DWORD oldProtect = 0;
	VirtualProtectEx(ctx->hProc, (LPVOID)dest, size, PAGE_EXECUTE_READWRITE, &oldProtect);
	WriteProcessMemory(ctx->hProc, (LPVOID)dest, source, size, &written);
	VirtualProtectEx(ctx->hProc, (LPVOID)dest, size, oldProtect, &oldProtect);
	return written;
}

EZAPI remote_getregs(struct ezinj_ctx *ctx, regs_t *regs){
	regs->ContextFlags = CONTEXT_ALL;
	if(GetThreadContext(ctx->hThread, regs) == FALSE){
		return -1;
	}
	return 0;
}

EZAPI remote_setregs(struct ezinj_ctx *ctx, regs_t *regs){
	regs->ContextFlags = CONTEXT_ALL;
	if(SetThreadContext(ctx->hThread, regs) == FALSE){
		return -1;
	}
	return 0;
}

#define USE_EXTERNAL_DEBUGGER

static EZAPI _get_user_tid(struct ezinj_ctx *ctx, DWORD entryTid, DWORD *pTid){
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;

	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, ctx->target);
	if(hThreadSnap == INVALID_HANDLE_VALUE){
		PERROR("CreateToolhelp32Snapshot failed");
		return -1;
	}

	intptr_t rc = -1;

	DWORD lastTid = 0;
	do {
		if(!Thread32First(hThreadSnap, &te32)){
			PERROR("Thread32First");
			break;
		}

		do {
			if(te32.th32OwnerProcessID != ctx->target){
				continue;
			}
			if(te32.th32ThreadID != entryTid){
				lastTid = te32.th32ThreadID;
				break;
			}
		} while(Thread32Next(hThreadSnap, &te32));
		rc = 0;
	} while(0);

	CloseHandle(hThreadSnap);
	*pTid = lastTid;
	return rc;
}

EZAPI remote_wait(struct ezinj_ctx *ctx, int expected_signal){
	UNUSED(expected_signal);

	DEBUG_EVENT *ev = &ctx->ev;
	DWORD target_tid = 0;

	/**
	 * on resume, the thread exits the debug status
	 * we loop until the payload emits the breakpoint
	 **/
	while(1){
		if(WaitForDebugEvent(ev, INFINITE) == FALSE){
			return -1;
		}
		DBG("Received Debug Event: %lu", ev->dwDebugEventCode);
		if(ev->dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT){
			DBG("EXIT_PROCESS_DEBUG_EVENT");
			// remote process is exiting, this is unexpected
			return -1;
		}
		else if(ev->dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT){
			DBG("CREATE_PROCESS_DEBUG_EVENT");
			ctx->hThread = ev->u.CreateProcessInfo.hThread;
			//DBG("Initial TID: %lu", GetThreadId(ctx->hThread));
			CloseHandle(ev->u.CreateProcessInfo.hFile);
		}
		else if(ev->dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT){
			DBG("CREATE_THREAD_DEBUG_EVENT");
			DBG("Thread ID: %lu", ev->dwThreadId);
		}
		else if(ev->dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT){
			DBG("EXIT_THREAD_DEBUG_EVENT");
			DBG("Thread ID: %lu", ev->dwThreadId);
		}
		else if(ev->dwDebugEventCode == LOAD_DLL_DEBUG_EVENT){
			DBG("LOAD_DLL_DEBUG_EVENT");
			CloseHandle(ev->u.LoadDll.hFile);
			LPVOID ptrAddr = ev->u.LoadDll.lpImageName;
			do {
				if(ptrAddr == NULL){
					break;
				}
				LPVOID ptr = NULL;
				remote_read(ctx, &ptr, (uintptr_t)ptrAddr, sizeof(LPVOID));
				if(ptr == NULL){
					break;
				}

				uint8_t buf[MAX_PATH];
				remote_read(ctx, buf, (uintptr_t)ptr, sizeof(buf));
				if(ev->u.LoadDll.fUnicode){
					DBG("LoadDLL[W]: %p -> %ls", ev->u.LoadDll.lpBaseOfDll, (wchar_t *)buf);
				} else {
					DBG("LoadDLL[A]: %p -> %s", ev->u.LoadDll.lpBaseOfDll, (char *)buf);
				}
			} while(0);
		}
		/**
		 * we swallow all process,thread and DLL events
		 * we then stop when we hit the first thread breakpoint
		 **/
		if(ev->dwDebugEventCode == EXCEPTION_DEBUG_EVENT){
			DBG("Got exception, tid: %lu", ev->dwThreadId);
			if(ev->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT){
				DBG("Got debugbreak, tid: %lu", ev->dwThreadId);
				break;
			}
			DBG("Unknown exception, target will likely crash");
			DBG("ExceptionCode: 0x%08lX", ev->u.Exception.ExceptionRecord.ExceptionCode);
			DBG("ExceptionAddr: %p", ev->u.Exception.ExceptionRecord.ExceptionAddress);
			#ifdef USE_EXTERNAL_DEBUGGER
			DBG("Press Enter to continue");
			getchar();
			#endif
		}
		ContinueDebugEvent(ev->dwProcessId, ev->dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
		if(ev->dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT){
			DBG("Thread resumed, waiting for debugbreak");
		}
	}
	DBG("Ready");

	/**
	 *  we stopped on a breakpoint
	 * get a handle to the thread that generated this event
	 **/
	/*
	if(ctx->hThread == NULL || ctx->hThread == INVALID_HANDLE_VALUE){
		ctx->hThread = OpenThread(THREAD_ALL_ACCESS, false, userTid);
		if(ctx->hThread == INVALID_HANDLE_VALUE){
			PERROR("OpenThread failed");
			return -1;
		}
	}
	*/
#if 0
	DBG("Thread ID: %lu", ev->dwThreadId);
	DWORD userTid = 0;
	if(_get_user_tid(ctx, ev->dwThreadId, &userTid) < 0){
		ERR("_get_user_tid failed");
		return -1;
	}
	DBG("Target Thread ID: %lu", userTid);
	//ctx->target_tid = userTid;
	ctx->hThread = OpenThread(THREAD_ALL_ACCESS, false, userTid);
	if(ctx->hThread == INVALID_HANDLE_VALUE){
		PERROR("OpenThread failed");
		return -1;
	}
#endif
	return 0;
}

EZAPI remote_sc_check(struct ezinj_ctx *ctx){
	return 0;
}
