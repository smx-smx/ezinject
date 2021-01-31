#ifndef __EZINJECT_CRT_H
#define __EZINJECT_CRT_H

#include <stdint.h>
#include "ezinject.h"

typedef void *(*crt_thread_func_t)(void *arg);

struct crt_ctx {
	struct injcode_bearing *shared_br;
	struct injcode_bearing *local_br;
};

EZAPI crt_thread_create(struct crt_ctx *ctx, crt_thread_func_t pfnThreadEntry);
EZAPI crt_thread_notify(struct crt_ctx *ctx);

#endif