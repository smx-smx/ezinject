/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#ifndef __EZINJECT_UTIL_H
#define __EZINJECT_UTIL_H

#include "config.h"

#ifdef EZ_TARGET_ANDROID
// workaround header dependency bug with Android NDK r14b
// error: unknown type name '__va_list'
#include <err.h>
#endif

#include <stdio.h>

#include "ezinject.h"

enum code_data_transform {
    // as-is
    CODE_DATA_NONE = 0,
    // follow PLT stub (e.g. HP-UX)
    CODE_DATA_DEREF,
    // undo architectural shift (e.g. ARM Thumb)
    CODE_DATA_BYTES,
    CODE_DATA_DPTR,
};

void hexdump(void *pAddressIn, long lSize);
ez_addr sym_addr(void *handle, const char *sym_name, ez_addr lib);
char *os_realpath(const char *path);
void *code_data(void *code, enum code_data_transform transform);

/* one parsed /proc/pid/maps line (Linux format) */
struct ezinj_map_entry {
	uintptr_t start;
	uintptr_t end;
	char perms[8];
	unsigned long offset;
	unsigned long inode;
	char path[256];
	int has_path;
};

/* parse a /proc/pid/maps line. 0 = usable entry, -1 = garbage.
 * Linux-only implementation (os/linux/util.c); other targets must
 * not call it. NB: suppressed %*x conversions do not count toward
 * sscanf's return value, hence the < 5 / < 6 thresholds. */
int os_parse_maps_line(const char *line, struct ezinj_map_entry *out);

#endif