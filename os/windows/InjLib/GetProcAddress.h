#ifndef __GETPROCADDR_H__
#define __GETPROCADDR_H__

DWORD NameToOrdinal(HMODULE hModule, LPCSTR lpProcName);
FARPROC _GetProcAddress(HMODULE hModule, DWORD Ordinal);
int GetProcLength(HMODULE hModule, DWORD Ordinal);

#endif // __GETPROCADDR_H__