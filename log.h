#ifndef __LOG_H
#define __LOG_H

#include <stdio.h>
#include <errno.h>
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
#ifdef DEBUG
#define DBG(fmt, ...) LOG(V_DBG, "[DEBG] " fmt, ##__VA_ARGS__)
#define LOG_PREFIX "[" __FILE__ ":" STRINGIFY(__LINE__) "] "
#else
#define DBG(fmt, ...)
#define LOG_PREFIX ""
#endif

#define DBGPTR(p) DBG("%s=%p", #p, (void *)p)

#define LOG(verb, fmt, ...) do{if((int)verbosity>=verb){printf(LOG_PREFIX fmt "\n", ##__VA_ARGS__);}}while(0)
#define INFO(fmt, ...) LOG(V_INFO, "[INFO] " fmt, ##__VA_ARGS__)
#define WARN(fmt, ...) LOG(V_WARN, "[WARN] " fmt, ##__VA_ARGS__)
#define ERR(fmt, ...) LOG(V_ERR, "[ERR ] " fmt, ##__VA_ARGS__)

#define PERROR(str) ERR("%s: %s", str, strerror(errno));
#define CHECK(x) ({\
long _tmp = (x);\
DBG("%s = %lu", #x, _tmp);\
_tmp;})

#endif