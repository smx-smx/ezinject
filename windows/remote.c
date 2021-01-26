#include <windows.h>
#include <debugapi.h>
#include <sys/types.h>
#include <tlhelp32.h>

#include "ezinject.h"
#include "log.h"

static BOOL _get_secondary_thread(DWORD dwProcessId, DWORD dwThreadId, LPDWORD dwSecondaryThreadId){
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if(hSnap == INVALID_HANDLE_VALUE){
		return INVALID_HANDLE_VALUE;
	}

	THREADENTRY32 te;
	te.dwSize = sizeof(te);

	BOOL found = FALSE;
	DWORD threadsCount = 0;
	do {
		if(!Thread32First(hSnap, &te)){
			break;
		}

		do {
			/**
			 * from https://devblogs.microsoft.com/oldnewthing/20060223-14/?p=32173
			 * the only subtlety being the strange check that the size returned
			 * by the Thread32First function is large enough to emcompass
			 * the th32OwnerProcessID field that we need.
			 * This complexity is necessary due to the somewhat unorthodox way
			 * that the Thread32First and Thread32Next functions check structure sizes.
			 **/
			if(te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
							sizeof(te.th32OwnerProcessID)
			){
				if(te.th32OwnerProcessID == dwProcessId && threadsCount++ == 2){
					*dwSecondaryThreadId = te.th32ThreadID;
					found = TRUE;
					break;
				}
			}
		} while(Thread32Next(hSnap, &te));
	} while(0);
	CloseHandle(hSnap);

	return found;
}

EZAPI remote_attach(struct ezinj_ctx *ctx){
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, ctx->target);
	if(hProc == INVALID_HANDLE_VALUE){
		return -1;
	}
	if(remote_suspend(ctx) != 0){
		ERR("remote_suspend failed");
		return -1;
	}
	if(DebugSetProcessKillOnExit(FALSE) == FALSE){
		PERROR("DebugSetProcessKillOnExit failed");
		return -1;
	}
	ctx->hProc = hProc;
	
	/*HANDLE hThread = get_main_thread(ctx);
	if(hThread == INVALID_HANDLE_VALUE){
		ERR("get_main_thread failed");
		return -1;
	}
	ctx->hSecondaryThread = hThread;*/

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
	DBG("Resuming %u %u", ctx->ev.dwProcessId, ctx->ev.dwThreadId);
	CloseHandle(ctx->hPrimaryThread);
	if(ContinueDebugEvent(ctx->ev.dwProcessId, ctx->ev.dwThreadId, DBG_EXCEPTION_HANDLED) == FALSE){
		return -1;
	}
	return 0;
}

EZAPI remote_detach(struct ezinj_ctx *ctx){
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
	WriteProcessMemory(ctx->hProc, (LPVOID)dest, source, size, &written);
	return written;
}

EZAPI remote_getregs(struct ezinj_ctx *ctx, regs_t *regs){
	regs->ContextFlags = CONTEXT_ALL;
	if(GetThreadContext(ctx->hPrimaryThread, regs) == FALSE){
		return -1;
	}
	return 0;
}

EZAPI remote_setregs(struct ezinj_ctx *ctx, regs_t *regs){
	regs->ContextFlags = CONTEXT_ALL;
	if(SetThreadContext(ctx->hPrimaryThread, regs) == FALSE){
		return -1;
	}
	return 0;
}

EZAPI remote_syscall_trace_enable(struct ezinj_ctx *ctx, int enable){
	return 0;
}

EZAPI remote_syscall_step(struct ezinj_ctx *ctx){
	return 0;
}

#define USE_EXTERNAL_DEBUGGER

EZAPI remote_wait(struct ezinj_ctx *ctx){
	DEBUG_EVENT *ev = &ctx->ev;
	/**
	 * on resume, the thread exits the debug status
	 * we loop until the payload emits the breakpoint
	 **/
	while(1){
		if(WaitForDebugEvent(ev, INFINITE) == FALSE){
			return -1;
		}
		DBG("Received Debug Event: %u", ev->dwDebugEventCode);
		if(ev->dwDebugEventCode == LOAD_DLL_DEBUG_EVENT){
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

				char buf[MAX_PATH];
				remote_read(ctx, buf, (uintptr_t)ptr, sizeof(buf));
				if(ev->u.LoadDll.fUnicode){
					DBG("LoadDLL[W]: %p -> %ls", ev->u.LoadDll.lpBaseOfDll, buf);
				} else {
					DBG("LoadDLL[A]: %p -> %s", ev->u.LoadDll.lpBaseOfDll, buf);
				}

				CloseHandle(ev->u.LoadDll.hFile);
			} while(0);
		}
		/**
		 * we swallow all process,thread and DLL events
		 * we then stop when we hit the first thread breakpoint
		 **/
		if(ev->dwDebugEventCode == EXCEPTION_DEBUG_EVENT){
			if(ev->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT){
				DBG("Got debugbreak");
				break;	
			}
			DBG("Unknown exception, target will likely crash");
			DBG("ExceptionCode: 0x%08X", ev->u.Exception.ExceptionRecord.ExceptionCode);
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
	
	DWORD dwProcessId = GetProcessId(ctx->hProc);

	/**
	 *  we stopped on a breakpoint
	 * get a handle to the thread that generated this event
	 **/
	DWORD dwSecondaryThreadId;
	if(_get_secondary_thread(dwProcessId, ev->dwThreadId, &dwSecondaryThreadId) == FALSE){
		return -1;
	}
	DBG("Primary TID: %u", ev->dwThreadId);
	DBG("Secondary TID: %u", dwSecondaryThreadId);
	ctx->hPrimaryThread = OpenThread(THREAD_ALL_ACCESS, false, ev->dwThreadId);
	/*ctx->hSecondaryThread = OpenThread(THREAD_ALL_ACCESS, false, dwSecondaryThreadId);

	if(ctx->hPrimaryThread == INVALID_HANDLE_VALUE){
		PERROR("OpenThread (primary) failed");
		return -1;
	}
	if(ctx->hSecondaryThread == INVALID_HANDLE_VALUE){
		PERROR("OpenThread (secondary) failed");
		return -1;
	}*/
	return 0;
}