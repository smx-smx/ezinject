/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include "ezinject_util.h"

#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>

#include "ezinject_common.h"

typedef struct {
	void *addr_start;
	void *addr_end;
	char *perms;
	char *path;
	void *user_data;
} matcher_data_t;

typedef struct {
	char *substr;
	char **ignores;
} get_base_data_t;

typedef struct {
	int perms;
	size_t size;
} get_map_data_t;

typedef bool (*pfnMatcher)(matcher_data_t *user_data);

static void *_filter_maps(
	pfnMatcher matcher,
	pid_t pid, void *user_data,
	matcher_data_t *pResult
){
	char line[256];
	char path[128];
	void *start, *end;
	char perms[8];
	bool found = false;

	snprintf(line, 256, "/proc/%u/maps", pid);
	FILE *fp = fopen(line, "r");
	while(fgets(line, sizeof(line), fp) != NULL){
		strncpy(path, "[anonymous]", sizeof(path));

		int filled = sscanf(line, "%p-%p %s %*p %*x:%*x %*u %s", &start, &end, (char *)&perms, path);
		if(filled < 2){
			continue;
		}
		
		matcher_data_t matcher_data = {
			.addr_start = start,
			.addr_end = end,
			.perms = perms,
			.path = path,
			.user_data = user_data
		};
		if(matcher(&matcher_data)){
			found = true;
			memcpy(pResult, &matcher_data, sizeof(matcher_data));
			break;
		}
		
	}
	fclose(fp);

	return (found) ? start : NULL;
}

bool _get_base_cb(matcher_data_t *data){
	char *perms = data->perms;
	char *path = data->path;
	get_base_data_t *user_data = (get_base_data_t *)data->user_data;
	char *substr = user_data->substr;
	char **ignores = user_data->ignores;

	int sublen = 0;
	if(substr != NULL){
		sublen = strlen(substr);
	}

	// pointer to the last character in the path
	char *end = (char *)&path[0] + strlen(path);

	char *sub = NULL;
	if(substr != NULL){
		sub = strstr(path, substr);
		if(sub == NULL){
			// substring not found
			return false;
		}
	}

	if(ignores != NULL){
		bool skip = false;

		char **listPtr = ignores;
		while(*listPtr != NULL){
			if(strstr(path, *(listPtr++))){
				// found a match in the ignores list, skip this entry
				skip = true;
				break;
			}
		}

		if(skip){
			return false;
		}
	}

	// if we have no substring, get the first executable segment
	if(substr == NULL){
		if(strchr(perms, 'x') != NULL){
			return true;
		}
	} else {
		if(strchr(perms, 's') != NULL){
			// it's a shared semgent, skip it
			return false;
		}

		// skip the matched part
		sub += sublen;
		if(sub >= end){
			// we're at the end of the path string
			// it's a full match
			return true;
		}

		// check common version suffixes
		switch(*sub){
			case '.': //libc.
			case '-': //libc-
				return true;
		}
	}

	return false;
}

bool _find_map_cb(matcher_data_t *data){
	get_map_data_t *user_data = (get_map_data_t *)data->user_data;
	int perms = user_data->perms;
	size_t size = user_data->size;

	if(PTRDIFF(data->addr_end, data->addr_start) < size){
		return false;
	}
	if((perms & PROT_READ) == PROT_READ && strchr(data->perms, 'r') == NULL){
		return false;
	}
	if((perms & PROT_WRITE) == PROT_WRITE && strchr(data->perms, 'w') == NULL){
		return false;
	}
	if((perms & PROT_EXEC) == PROT_EXEC && strchr(data->perms, 'x') == NULL){
		return false;
	}

	return true;
}


void *get_base(pid_t pid, char *substr, char **ignores) {
	get_base_data_t user_data = {
		.substr = substr,
		.ignores = ignores
	};
	matcher_data_t result;
	memset(&result, 0x00, sizeof(result));
	return _filter_maps(_get_base_cb, pid, &user_data, &result);
}

void *get_base_ex(pid_t pid, char *substr, char **ignores, size_t *pSize){
	get_base_data_t user_data = {
		.substr = substr,
		.ignores = ignores
	};
	matcher_data_t result;
	memset(&result, 0x00, sizeof(result));
	void *base = _filter_maps(_get_base_cb, pid, &user_data, &result);
	if(base != NULL){
		*pSize = (uintptr_t)result.addr_end - (uintptr_t)result.addr_start;
	}
	return base;
}

void *find_map(pid_t pid, int perms, size_t size){
	get_map_data_t user_data = {
		.perms = perms,
		.size = size
	};
	matcher_data_t result;
	memset(&result, 0x00, sizeof(result));
	return _filter_maps(_find_map_cb, pid, &user_data, &result);
}
