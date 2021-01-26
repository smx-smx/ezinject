#ifndef __WINDOWS_UTIL_H
#define __WINDOWS_UTIL_H

#include <windows.h>
BOOL win32_errstr(DWORD dwErrorCode, LPTSTR pBuffer, DWORD cchBufferLength);

#endif