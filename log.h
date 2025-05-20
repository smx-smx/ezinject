/*
 * Copyright (C) 2025 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#ifndef __LOG_H
#define __LOG_H

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include "config.h"

enum verbosity_level {
	V_ERR = 0,
	V_WARN,
	V_INFO,
	V_DBG
};

typedef struct {
    enum verbosity_level verbosity;
    FILE *log_output;
    int log_leave_open;
} log_config_t;

void log_init(log_config_t *cfg);
void log_fini();
void log_puts(const char *str);
void log_printf(const char *format, ...);
void log_putchar(int ch);
void log_log(enum verbosity_level verbosity, const char *format, ...);
enum verbosity_level log_get_verbosity();
void log_set_verbosity(int verbosity);


#if __WORDSIZE == 64
#define LX "%lx"
#define LLX LX
#define LU "%lu"
#else
#define LX "%x"
#define LLX "%llx"
#define LU "%u"
#endif

#define STRINGIFY(x) STRINGIFY2(x)
#define STRINGIFY2(x) #x
//#ifdef DEBUG
#define DBG(fmt, ...) LOG(V_DBG, "[DEBG] " fmt, ##__VA_ARGS__)
#define LOG_PREFIX "[" __FILE__ ":" STRINGIFY(__LINE__) "] "
//#else
//#define DBG(fmt, ...)
//#define LOG_PREFIX ""
//#endif

#define DBGPTR(p) DBG("%s=%p", #p, (void *)p)

#define lputs(str) log_puts(str)
#define lprintf(fmt, ...) log_printf(fmt, ##__VA_ARGS__)
#define lputchar(ch) log_putchar(ch)

#define LOG(verb, fmt, ...) \
    log_log(verb, fmt "\n", ##__VA_ARGS__)

#define INFO(fmt, ...) LOG(V_INFO, "[INFO] " fmt, ##__VA_ARGS__)
#define WARN(fmt, ...) LOG(V_WARN, "[WARN] " fmt, ##__VA_ARGS__)
#define ERR(fmt, ...) LOG(V_ERR, "[ERR ] " fmt, ##__VA_ARGS__)

#if defined(EZ_TARGET_POSIX)
#define PERROR(str) ERR("%s: %s", str, strerror(errno));
#elif defined(EZ_TARGET_WINDOWS)
#include "os/windows/util.h"
#define PERROR(str) do { \
    char buf[256]; \
    DWORD errCode = GetLastError(); \
    if(win32_errstr(errCode, buf, sizeof(buf))) \
        ERR("%s: %s (0x%08lX)", str, buf, errCode); \
} while(0);
#endif
#define CHECK(x) ({\
uintptr_t _tmp = (x);\
DBG("%s = %"PRIxPTR, #x, (uintptr_t)(_tmp));\
_tmp;})

#endif
