/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#ifndef __EZINJECT_OS_BUILDER_H
#define __EZINJECT_OS_BUILDER_H

#include <stdint.h>
#include <stdbool.h>
#include "ezinject.h"

struct os_builder_ctx {
	char *pl_filename;
};

void os_pagesize_init(struct ezinj_ctx *ctx);
int  os_post_attach_wait(struct ezinj_ctx *ctx);
void os_strings_init(struct ezinj_ctx *ctx, struct ezinj_strings *strings, struct os_builder_ctx *os_ctx);
void os_bearing_setup(struct injcode_bearing *br, struct ezinj_ctx *ctx, struct os_builder_ctx *os_ctx);
void os_rcall_setup(struct ezinj_ctx *ctx, struct injcode_call *rcall, uintptr_t r_call_args);
bool os_forward_signal(struct ezinj_ctx *ctx, int status, bool syscall_mode);
void os_invoke_begin(struct ezinj_ctx *ctx, struct injcode_call *rcall);
uintptr_t os_alloc_retry(struct ezinj_ctx *ctx, uintptr_t result, size_t mapping_size);
int  os_pl_copy(struct ezinj_ctx *ctx, size_t mapping_size);
bool os_should_retry(struct ezinj_ctx *ctx, int err);
void os_plt_resolve(void);
void os_print_maps(void);

#endif
