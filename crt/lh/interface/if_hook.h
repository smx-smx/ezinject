/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#ifndef __LH_INTERFACE_HOOK_H
#define __LH_INTERFACE_HOOK_H

#include <stddef.h>
#include <stdint.h>

#define LHM_FN_COPY_BYTES 16

int unprotect(void *addr);
int inj_inject_library(const char *dllPath, int argc, char *argv[], void **out_libaddr);
void *inj_backup_function(void *original_code, size_t *num_saved_bytes, int opcode_bytes_to_restore);
int inj_replace_function(void *original_fn, void *replacement_fn);

#endif
