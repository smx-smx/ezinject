/*
 * hotpatch is a dll injection strategy.
 * Copyright (c) 2010-2011, Vikas Naresh Kumar, Selective Intellect LLC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *
 * * Neither the name of Selective Intellect LLC nor the
 *   names of its contributors may be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <linux/limits.h>
#include "linux_elf.h"
#include "log.h"

enum {
	PROCMAPS_PERMS_NONE = 0x0,
	PROCMAPS_PERMS_READ = 0x1,
	PROCMAPS_PERMS_EXEC = 0x2,
	PROCMAPS_PERMS_WRITE = 0x4,
	PROCMAPS_PERMS_PRIVATE = 0x8,
	PROCMAPS_PERMS_SHARED = 0x10
};

enum {
	PROCMAPS_FILETYPE_UNKNOWN, //0
	PROCMAPS_FILETYPE_EXE, //1
	PROCMAPS_FILETYPE_LIB, //2
	PROCMAPS_FILETYPE_DATA, //3
	PROCMAPS_FILETYPE_VDSO, //4
	PROCMAPS_FILETYPE_HEAP, //5
	PROCMAPS_FILETYPE_STACK, //6
	PROCMAPS_FILETYPE_SYSCALL //7
};

#define UNUSED(x) (void)x

void ld_procmaps_dump(struct ld_procmaps *pm) {
	if (!pm)
		return;
	LOG(4, "Pathname: %s", pm->pathname ? pm->pathname : "Unknown");
	LOG(4, "Address Start: " LX " End: " LX " Valid:" " %d Offset: " LU, pm->addr_begin, pm->addr_end, pm->addr_valid, (size_t) pm->offset);
	LOG(4, "Device Major: %d Minor: %d", pm->device_major, pm->device_minor);
	LOG(4, "Inode: " LU, (size_t) pm->inode);
	LOG(4, "Permissions: Read(%d) Write(%d) " "Execute(%d) Private(%d) Shared(%d)", (pm->permissions & PROCMAPS_PERMS_READ) ? 1 : 0, (pm->permissions & PROCMAPS_PERMS_WRITE) ? 1 : 0, (pm->permissions & PROCMAPS_PERMS_EXEC) ? 1 : 0, (pm->permissions & PROCMAPS_PERMS_PRIVATE) ? 1 : 0, (pm->permissions & PROCMAPS_PERMS_SHARED) ? 1 : 0);
	LOG(4, "Pathname length: " LU, pm->pathname_sz);
	LOG(4, "Filetype: %d", pm->filetype);
}

int ld_procmaps_parse(char *buf, size_t bufsz, struct ld_procmaps *pm, const char *appname) {
	UNUSED(bufsz);
	if (!buf || !pm) {
		ERR("Invalid arguments.");
		return -1;
	}
	/* this is hardcoded parsing of the maps file */
	do {
		char *token = NULL;
		char *save = NULL;
		int idx, err;
		memset(pm, 0, sizeof(*pm));
		token = strtok_r(buf, "-", &save);
		if (!token)
			break;
		errno = 0;
		pm->addr_begin = (uintptr_t) strtoul(token, NULL, 16);
		err = errno;
		pm->addr_valid = (err == ERANGE || err == EINVAL) ? false : true;
		if (!pm->addr_valid) {
			LOG(2, "Strtoul error(%s) in parsing %s", strerror(err), token);
		}
		token = strtok_r(NULL, " ", &save);
		if (!token)
			break;
		errno = 0;
		pm->addr_end = (intptr_t) strtoul(token, NULL, 16);
		err = errno;
		pm->addr_valid = (err == ERANGE || err == EINVAL) ? false : true;
		if (!pm->addr_valid) {
			LOG(2, "Strtoul error(%s) in parsing %s", strerror(err), token);
		}
		token = strtok_r(NULL, " ", &save);
		if (!token)
			break;
		pm->permissions = PROCMAPS_PERMS_NONE;
		for (idx = strlen(token) - 1; idx >= 0; --idx) {
			switch (token[idx]) {
			case 'r':
				pm->permissions |= PROCMAPS_PERMS_READ;
				break;
			case 'w':
				pm->permissions |= PROCMAPS_PERMS_WRITE;
				break;
			case 'x':
				pm->permissions |= PROCMAPS_PERMS_EXEC;
				break;
			case 'p':
				pm->permissions |= PROCMAPS_PERMS_PRIVATE;
				break;
			case 's':
				pm->permissions |= PROCMAPS_PERMS_SHARED;
				break;
			case '-':
				break;
			default:
				LOG(2, "Unknown flag: %c", token[idx]);
				break;
			}
		}
		token = strtok_r(NULL, " ", &save);
		if (!token)
			break;
		errno = 0;
		pm->offset = (off_t) strtoul(token, NULL, 16);
		err = errno;
		if (err == ERANGE || err == EINVAL) {
			LOG(2, "Strtoul error(%s) in parsing %s", strerror(err), token);
		}
		token = strtok_r(NULL, ":", &save);
		if (!token)
			break;
		pm->device_major = (int)strtol(token, NULL, 10);
		token = strtok_r(NULL, " ", &save);
		if (!token)
			break;
		pm->device_minor = (int)strtol(token, NULL, 10);
		token = strtok_r(NULL, " ", &save);
		if (!token)
			break;
		pm->inode = (ino_t) strtoul(token, NULL, 10);
		token = strtok_r(NULL, "\n", &save);
		if (!token)
			break;
		pm->pathname_sz = strlen(token);
		pm->pathname = calloc(sizeof(char), pm->pathname_sz + 1);
		if (!pm->pathname) {
			ERR("malloc");
			pm->pathname = NULL;
			pm->pathname_sz = 0;
			break;
		}
		/* trim the extra spaces out */
		save = token;
		/* find the real path names */
		if ((token = strchr(save, '/'))) {
			memcpy(pm->pathname, token, strlen(token));
			if (strstr(pm->pathname, ".so") || strstr(pm->pathname, ".so.")) {
				pm->filetype = PROCMAPS_FILETYPE_LIB;
			} else {
				struct stat statbuf;
				pm->filetype = PROCMAPS_FILETYPE_DATA;
				memset(&statbuf, 0, sizeof(statbuf));
				if (stat(pm->pathname, &statbuf) >= 0) {
					ino_t inode1 = statbuf.st_ino;
					memset(&statbuf, 0, sizeof(statbuf));
					if (stat(appname, &statbuf) >= 0) {
						if (statbuf.st_ino == inode1)
							pm->filetype = PROCMAPS_FILETYPE_EXE;
					}
				} else {
					int err = errno;
					LOG(2, "Unable to stat file %s. Error:" " %s", pm->pathname, strerror(err));
				}
			}
		} else if ((token = strchr(save, '['))) {
			memcpy(pm->pathname, token, strlen(token));
			if (strstr(pm->pathname, "[heap]")) {
				pm->filetype = PROCMAPS_FILETYPE_HEAP;
			} else if (strstr(pm->pathname, "[stack]")) {
				pm->filetype = PROCMAPS_FILETYPE_STACK;
			} else if (strstr(pm->pathname, "[vdso]")) {
				pm->filetype = PROCMAPS_FILETYPE_VDSO;
			} else if (strstr(pm->pathname, "[vsyscall")) {
				pm->filetype = PROCMAPS_FILETYPE_SYSCALL;
			} else {
				LOG(2, "Unknown memory map: %s", pm->pathname);
				pm->filetype = PROCMAPS_FILETYPE_UNKNOWN;
			}
		} else {
			memcpy(pm->pathname, token, strlen(token));
			pm->filetype = PROCMAPS_FILETYPE_UNKNOWN;
		}
	} while (0);
	return 0;
}

struct ld_procmaps *ld_load_maps(pid_t pid, size_t * num) {
	char filename[PATH_MAX];
	char appname[PATH_MAX];
	FILE *ff = NULL;
	const size_t bufsz = 4096;
	char *buf = NULL;
	size_t mapmax = 0;
	size_t mapnum = 0;
	struct ld_procmaps *maps = NULL;
	if (pid == 0) {
		ERR("Invalid PID: %d", pid);
		return NULL;
	}
#ifdef __FreeBSD__
	// This is hacky we should do native BSD /proc/xx/map
	snprintf(filename, PATH_MAX, "/compat/linux/proc/%d/maps", pid);
	snprintf(appname, PATH_MAX, "/proc/%d/file", pid);
#else
	snprintf(filename, PATH_MAX, "/proc/%d/maps", pid);
	snprintf(appname, PATH_MAX, "/proc/%d/exe", pid);
#endif
	LOG(2, "Using Proc Maps from %s", filename);
	LOG(2, "Using Proc Exe from %s", appname);

	do {
		buf = calloc(sizeof(char), bufsz);
		if (!buf) {
			ERR("malloc");
			break;
		}
		ff = fopen(filename, "r");
		if (!ff) {
			ERR("open");
			break;
		}
		while (fgets(buf, bufsz, ff))
			mapmax++;
		LOG(1, "Max number of mappings present: " LU, mapmax);
		fseek(ff, 0L, SEEK_SET);
		maps = calloc(mapmax, sizeof(*maps));
		if (!maps) {
			ERR("malloc");
			break;
		}
		LOG(1, "Allocated memory to load proc maps");
		memset(buf, 0, bufsz);
		mapnum = 0;
		while (fgets(buf, bufsz, ff)) {
			struct ld_procmaps *pm = &maps[mapnum];
			LOG(4, "Parsing %s", buf);
			if (ld_procmaps_parse(buf, bufsz, pm, appname) < 0) {
				LOG(1, "Parsing failure. Ignoring.");
				continue;
			}
			ld_procmaps_dump(pm);
			mapnum++;
		}
		if (num)
			*num = mapnum;
		else
			LOG(3, "Cannot return size of maps object.");
	} while (0);
	if (buf)
		free(buf);
	if (ff)
		fclose(ff);
	return maps;
}

void ld_free_maps(struct ld_procmaps *maps, size_t num) {
	if (maps && num > 0) {
		size_t idx;
		for (idx = 0; idx < num; ++idx) {
			if (maps[idx].pathname)
				free(maps[idx].pathname);
			maps[idx].pathname = NULL;
		}
		free(maps);
		maps = NULL;
	}
}

int ld_find_library(struct ld_procmaps *maps, const size_t mapnum, const char *libpath, bool inode_match, struct ld_procmaps **lib) {
	if (!maps && !libpath) {
		LOG(3, "Invalid arguments.");
		return -1;
	} else {
		size_t idx;
		bool found = false;
		ino_t inode = 0;
		bool nonlib_match = false;
		bool exact_match = false;
		if (inode_match) {
			struct stat statbuf;
			if (stat(libpath, &statbuf) < 0) {
				int err = errno;
				LOG(1, "Unable to get inode for %s. Error: %s", libpath, strerror(err));
				return -1;
			}
			inode = statbuf.st_ino;
		} else {
			LOG(2, "Not doing an inode match.");
			nonlib_match = (strchr(libpath, '[') || strchr(libpath, ']')) ? true : false;
			if (nonlib_match)
				LOG(2, "Found '[' or ']' in %s", libpath);
			exact_match = (strchr(libpath, '/')) ? true : false;
			if (exact_match)
				LOG(2, "Found '/' in %s. Doing an exact match search", libpath);
			if (!nonlib_match && !exact_match)
				LOG(2, "Doing best substring search for %s.", libpath);
		}

		for (idx = 0; idx < mapnum; ++idx) {
			const struct ld_procmaps *pm = &maps[idx];
			if (!pm->pathname)
				continue;

			/* first try inode match. the libraries can be symlinks and
			 * all that
			 */
			if (inode_match) {
				/* if it has no inode, we do not support it */
				if (pm->inode == 0)
					continue;
				found = (pm->inode == inode) ? true : false;
			} else {
				/* Now try string match.
				 * 1. if the string contains a '[' or ']' then do a substring
				 * match
				 * 2. if the string contains a '/' then do an exact match
				 * 3. else substring search all libs and return the first one
				 * with a valid inode
				 */
				if (nonlib_match) {
					/* we're looking for a non-library or a non-exe file or a
					 * non-data file
					 */
					if (pm->filetype == PROCMAPS_FILETYPE_VDSO ||
						pm->filetype == PROCMAPS_FILETYPE_HEAP ||
						pm->filetype == PROCMAPS_FILETYPE_STACK ||
						pm->filetype == PROCMAPS_FILETYPE_SYSCALL) {
						/* doing a substring match to be safe */
						found = strstr(pm->pathname, libpath) != NULL ? true : false;
					}
				} else {
					if (pm->inode == 0)
						continue;
					//if ((pm->filetype != PROCMAPS_FILETYPE_LIB) && (pm->filetype != PROCMAPS_FILETYPE_EXE))
					//	continue;

					/* we're doing an exact match */
					if (exact_match) {
						found = strcmp(libpath, pm->pathname) == 0 ? true : false;
					} else {

						/* do a substring match for best fit. If the string
						 * matches then check if the next character is not an
						 * alphabet and is a . or a -
						 */
						char *sub = strstr(pm->pathname, libpath);
						found = false;
						if (sub) {
							size_t alen = strlen(libpath);
							if (sub[alen] == '.' || sub[alen] == '-' || sub[alen] == '\0')
								found = true;
							else if ((libpath[0] == '\0') && (pm->filetype == PROCMAPS_FILETYPE_EXE))
								found = true;
						}
					}
				}
			}
			if (found) {
				LOG(2, "Found index (" LU ") matching.", idx);
				LOG(1, "Found entry '%s' matching '%s'", pm->pathname, libpath);
				break;
			}
		}
		if (!found) {
			LOG(1, "Library '%s' not found in procmaps", libpath);
			return -1;
		}
		if (found && lib) {
			*lib = &maps[idx];
		}
	}
	return 0;
}

uintptr_t ld_symbols_get_addr(const struct elf_symbol *syms, size_t syms_num, uintptr_t addr_begin,
								const char *symbol, size_t *size)
{
	size_t idx = 0;
	uintptr_t ptr = 0;
	for (idx = 0; idx < syms_num; ++idx) {
		if (strcmp(symbol, syms[idx].name) == 0) {
			LOG(2, "Found %s in symbol list at " "" LU " with address offset " LX, symbol, idx, syms[idx].address);
			if (size != NULL)
				*size = syms[idx].size;
			if (syms[idx].address > addr_begin)
				ptr = syms[idx].address;
			else
				ptr = syms[idx].address + addr_begin;
			break;
		}
	}
	return ptr;
}

void ld_free_symbols(struct elf_symbol *syms, size_t syms_num){
	/* free memory for all to avoid mem-leaks */
	size_t idx;
	for (idx = 0; idx < syms_num; ++idx) {
		if (syms[idx].name)
			free(syms[idx].name);
		syms[idx].name = NULL;
	}
	free(syms);
}

uintptr_t ld_find_address(const struct ld_procmaps * lib, const char *symbol, size_t * size) {
	uintptr_t ptr = 0;
	if (lib && symbol && lib->pathname) {
		size_t syms_num = 0;
		struct elf_symbol *syms = exe_load_symbols(lib->pathname, &syms_num, NULL, NULL, NULL);
		if (syms && syms_num > 0) {
			LOG(1, LU " symbols found in %s", syms_num, lib->pathname);
			qsort(syms, syms_num, sizeof(*syms), elf_symbol_cmpqsort);
			ptr = ld_symbols_get_addr(syms, syms_num, lib->addr_begin, symbol, size);
			ld_free_symbols(syms, syms_num);
			syms_num = 0;
		} else {
			LOG(1, "No symbols found in %s", lib->pathname);
		}
	} else {
		ERR("Invalid arguments.");
	}
	return ptr;
}
