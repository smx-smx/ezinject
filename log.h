#ifndef __LOG_H
#define __LOG_H

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "config.h"

extern enum verbosity_level
{
	V_ERR = 0,
	V_WARN,
	V_INFO,
	V_DBG
} verbosity;

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

#ifdef LOG_USE_FILE
#define LOG_RESERVED_HANDLE __ghLog
#else
#define LOG_RESERVED_HANDLE stdout
#endif

#define __LOG_DECLARE_VERBOSITY(verb) \
    enum verbosity_level verbosity = verb

#ifdef LOG_USE_FILE
#include <stdlib.h>
extern FILE *LOG_RESERVED_HANDLE;

#define LOG_SETUP(verb) \
    FILE *LOG_RESERVED_HANDLE; \
    __LOG_DECLARE_VERBOSITY(verb)


#define LOG_INIT(filePath) do { \
    LOG_RESERVED_HANDLE = fopen(filePath, "w+"); \
    if(LOG_RESERVED_HANDLE == NULL){ \
        fprintf(stderr, "Cannot open log file '%s' for writing\n", filePath); \
        abort(); \
    } \
    setvbuf(LOG_RESERVED_HANDLE, NULL, _IONBF, 0); \
} while(0);
#define LOG_FINI() fclose(LOG_RESERVED_HANDLE);
#else
#define LOG_SETUP(verb) __LOG_DECLARE_VERBOSITY(verb)
#define LOG_INIT(filePath)
#define LOG_FINI()
#endif

#define lputs(str) fputs(str "\n", LOG_RESERVED_HANDLE)
#define lprintf(fmt, ...) fprintf(LOG_RESERVED_HANDLE, fmt, ##__VA_ARGS__)
#define lputchar(ch) fputc(ch, LOG_RESERVED_HANDLE)

#define LOG(verb, fmt, ...) do{ \
    if((int)verbosity>=verb) lprintf(LOG_PREFIX fmt "\n", ##__VA_ARGS__); \
} while(0)

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
long _tmp = (x);\
DBG("%s = %lu", #x, _tmp);\
_tmp;})

#endif