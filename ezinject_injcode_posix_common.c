/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */

void PLAPI inj_puts(struct injcode_ctx *ctx, char *str){
#ifdef DEBUG
	struct injcode_bearing *br = ctx->br;
	if(str == NULL){
		return;
	}

	int l;
	for(l=0; str[l] != 0x00; l++);
	br->libc_syscall(__NR_write, ctx->log_handle, str, l);
	char nl = '\n';

	br->libc_syscall(__NR_write, ctx->log_handle, &nl, 1);
#endif
}
