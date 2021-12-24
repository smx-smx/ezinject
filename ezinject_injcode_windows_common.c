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

	HANDLE h = STD_OUTPUT_HANDLE;

	DWORD nWritten = 0;

	int l = 0;
	char *p = str;
	while(*(p++)) ++l;
	br->WriteFile(h, str, l, &nWritten, NULL);

	char nl[2];
	nl[0] = '\r'; nl[1] = '\n';
	br->WriteFile(h, nl, sizeof(nl), &nWritten, NULL);
#endif
}
