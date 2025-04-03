/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */

#include "InjLib/Remote.h"
#include "ezinject.h"
#include "ezinject_injcode.h"

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
	if(!Initialization()){
		ERR("InjLib Initialization failed");
		return -1;
	}

	if(OSWinNT){
		if(_grant_debug_privileges() < 0){
			ERR("_grant_debug_privileges failed");
			return -1;
		}
	}

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, ctx->target);
	if(hProc == NULL || hProc == INVALID_HANDLE_VALUE){
		PERROR("OpenProcess failed");
		return -1;
	}
	ctx->hProc = hProc;

	DWORD main_tid = _GetProcessThread(ctx->target);
	DBG("main_tid: %lu", main_tid);
	HANDLE hThread = _OpenThread(THREAD_ALL_ACCESS, FALSE, main_tid);
	if(hThread == NULL || hThread == INVALID_HANDLE_VALUE){
		PERROR("OpenThread");
		return -1;
	}
	ctx->hThread = hThread;

	if(remote_suspend(ctx) != 0){
		ERR("remote_suspend failed");
		return -1;
	}
	return 0;
}

EZAPI remote_suspend(struct ezinj_ctx *ctx){
	if(SuspendThread(ctx->hThread) == (DWORD)-1){
		PERROR("SuspendThread");
		return -1;
	}

	return 0;
}

EZAPI remote_continue(struct ezinj_ctx *ctx, int signal){
	UNUSED(signal);

	if(ResumeThread(ctx->hThread) == (DWORD)-1){
		/*PERROR("ResumeThread");
		return -1;
		*/
	}
	return 0;
}

EZAPI remote_step(struct ezinj_ctx *ctx, int signal){
	return -1;
}

EZAPI remote_detach(struct ezinj_ctx *ctx){
	remote_continue(ctx, 0);
	return 0;
}

EZAPI remote_read(struct ezinj_ctx *ctx, void *dest, uintptr_t source, size_t size){
	SIZE_T read = 0;
	ReadProcessMemory(ctx->hProc, (LPCVOID)source, dest, size, &read);
	return read;
}

EZAPI remote_write(struct ezinj_ctx *ctx, uintptr_t dest, void *source, size_t size){
	SIZE_T written = 0;
	DWORD oldProtect = 0;
	VirtualProtectEx(ctx->hProc, (LPVOID)dest, size, PAGE_EXECUTE_READWRITE, &oldProtect);
	WriteProcessMemory(ctx->hProc, (LPVOID)dest, source, size, &written);
	VirtualProtectEx(ctx->hProc, (LPVOID)dest, size, oldProtect, &oldProtect);
	return written;
}

/**
 * GetThreadContext and SetThreadContext can be async! (at least they are on x64!)
 * For x64, Microsoft saves the registers in 2 separate, non-atomic operations:
 * 1) non-volatile registers (like RIP) are read/written immediately in kernel-land
 * 2) volatile registers (Rbx, Rbx, etc.) are read/written in userland by an APC call!
 *
 * when the thread is resumed, it will run the queued APC by jumping to an ASM snippet
 * (not dissimilar from setjmp/longjmp) that will either save or restore the volatile registers.
 *
 * I'm not exactly sure why Microsoft implemented it like this
 * (and I would love to know why), so if you happen to have some information, drop me a message
 *
 * the implications are that:
 * - we must not be in a system call to capture sane register values
 * (or else the kernel will overwrite the register values with the syscall result)
 * - we must allow the thread to run for the APC to execute
 * (or else we will not get the new volatile register values)
 *
 * in order to workaround this, we implement the following logic:
 * NOTE: the thread *MUST* be suspended when calling this function
 *
 * 1. get the non-volatile registers (CONTEXT_CONTROL), which includes PC
 * - this will be needed to restore the original program state later on
 * 2. modify PC to jump to a trap (NOP + endless loop) that we previously wrote to SC
 * 3. resume the thread
 * - this runs the pending APC, and commits volatile registers
 * 4. wait for the endless loop to hit
 * 5. now that we're in a controlled state, we can read volatile registers
 * 6. suspend the thread
 * 7. merge the newly obtained register values with the original PC
 *
 * NOTE: the caller is expected to restore the context to continue execution
 *
 * References:
 * - https://www.lodsb.com/why-ntsetcontextthread-destroys-volatile-registers
 * - https://gist.github.com/NtRaiseHardError/ee7ee5edce7c0c11c8bf4e6ad24973a3#file-imagine-needing-writeprocessmemory-and-createremotethread-c-L57-L62
 * - https://undev.ninja/nina-x64-process-injection/
 * - https://stackoverflow.com/a/37909524/11782802
 */
static EZAPI _remote_hijack(struct ezinj_ctx *ctx, regs_t *regs_save){
	memset(regs_save, 0x00, sizeof(*regs_save));
	// get original PC
	regs_save->ContextFlags = CONTEXT_CONTROL;
	if(GetThreadContext(ctx->hThread, regs_save) == FALSE){
		PERROR("GetThreadContext failed");
		return -1;
	}

	regs_t regs;
	memcpy(&regs, regs_save, sizeof(regs));

	uintptr_t new_pc = remote_sc_get_trap_start();
	DBG("PC Detour: %p -> %p", VPTR(REG(regs, REG_PC)), VPTR(new_pc));

	// write detour PC value
	REG(regs, REG_PC) = new_pc;
	if(SetThreadContext(ctx->hThread, &regs) == FALSE){
		PERROR("SetThreadContext failed");
		return -1;
	}

	// let the process run the detour
	remote_continue(ctx, 0);

	// wait for the endless jump to hit (after the NOPs)
	uintptr_t jmp_addr = remote_sc_get_trap_stop();
	regs.ContextFlags = CONTEXT_ALL;
	DBG("Waiting for trap hit at %p", VPTR(jmp_addr));
	for(;;){
		// sample new register values
		if(GetThreadContext(ctx->hThread, &regs) == FALSE){
			PERROR("GetThreadContext failed");
			return -1;
		}
		//DBG("0x"LX", 0x"LX, REG(regs, REG_PC), jmp_addr);
		if(REG(regs, REG_PC) == jmp_addr){
			DBG("trap hit!");
			break;
		}
		Sleep(50);
	}

	if(remote_suspend(ctx) < 0){
		ERR("remote_suspend failed");
	}

	// get the original PC value before the overwrite
	uintptr_t orig_pc = REG(*regs_save, REG_PC);

	// overwrite registers with the new sample
	memcpy(regs_save, &regs, sizeof(regs));

	// restore the original PC
	// which is the only register that was modified in the trap
	REG(*regs_save, REG_PC) = orig_pc;
	return 0;
}

EZAPI remote_getregs(struct ezinj_ctx *ctx, regs_t *regs){
	// migrate the thread to a safe well-known state
	// and get its original registers
	if(_remote_hijack(ctx, regs) != 0){
		ERR("_remote_hijack() failed");
		return -1;
	}
	// restore original regs
	if(SetThreadContext(ctx->hThread, regs) == FALSE){
		PERROR("SetThreadContext");
		return -1;
	}
	return 0;
}

EZAPI remote_setregs(struct ezinj_ctx *ctx, regs_t *regs){
	// migrate the thread to a safe well-known state
	// and get its original registers
	regs_t regs_save;
	if(_remote_hijack(ctx, &regs_save) != 0){
		ERR("_remote_hijack() failed");
		return -1;
	}

	// set the desired registers (with thread suspended)
	regs->ContextFlags = CONTEXT_ALL;
	if(SetThreadContext(ctx->hThread, regs) == FALSE){
		PERROR("SetThreadContext");
		return -1;
	}

	// we need to do this again
	// to flush the APC queue and commit the volatile registers
	// from the previous SetThreadContext call
	if(_remote_hijack(ctx, &regs_save) != 0){
		ERR("_remote_hijack() failed");
		return -1;
	}

	// restore original regs
	if(SetThreadContext(ctx->hThread, regs) == FALSE){
		PERROR("SetThreadContext");
		return -1;
	}

	return 0;
}

#define USE_EXTERNAL_DEBUGGER

#if 0
static EZAPI _get_first_thread(struct ezinj_ctx *ctx, DWORD *pTid){
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;

	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, ctx->target);
	if(hThreadSnap == INVALID_HANDLE_VALUE){
		PERROR("CreateToolhelp32Snapshot failed");
		return -1;
	}

	DWORD tid = 0;
	do {
		if(!Thread32First(hThreadSnap, &te32)){
			PERROR("Thread32First");
			break;
		}

		do {
			if(te32.th32OwnerProcessID != ctx->target){
				continue;
			}
			tid = te32.th32ThreadID;
			break;
		} while(Thread32Next(hThreadSnap, &te32));
		rc = 0;
	} while(0);

	CloseHandle(hThreadSnap);
	*pTid = lastTid;

	if(tid == 0) return -1;
	return 0;
}

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
#endif

EZAPI remote_wait(struct ezinj_ctx *ctx, int expected_signal){
	UNUSED(expected_signal);

	regs_t regs;
	UNUSED(regs);

	while(1){
		uintptr_t ezstate = 0;
		if(remote_read(ctx,
			&ezstate, ctx->r_ezstate_addr,
			sizeof(ezstate)) != sizeof(ezstate)
		){
			ERR("remote_read failed");
			return -1;
		}

		// check for signaled state
		if(ezstate == EZST1){
			DBG("Ready");
			return 0;
		}

		Sleep(50);
	}

	/*while(1){
		nSameCount = 0;
		if(remote_getregs(ctx, &regs) < 0){
			ERR("remote_getregs failed");
			return -1;
		}
		initial_pc = REG(regs, REG_PC);

		while(nSameCount < 150){
			if(remote_getregs(ctx, &regs) < 0){
				ERR("remote_getregs failed");
				return -1;
			}
			last_pc = REG(regs, REG_PC);
			if(last_pc == initial_pc){
				++nSameCount;
			} else {
				// PC was not identical. repeat search
				break;
			}
			Sleep(1);
		}

		DBGPTR(REG(regs, REG_AX));

		if(nSameCount >= 150 && (uint32_t)REG(regs, REG_AX) == 0x455A535450){
			DBG("Ready");
			return 0;
		}
	}*/

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
