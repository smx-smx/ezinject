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

void *get_base(pid_t pid, char *substr, char **ignores) {
	char line[256];
	char path[128];
	void *base;
	char perms[8];
	bool found = false;

	int sublen = 0;
	if(substr != NULL){
		sublen = strlen(substr);
	}

	snprintf(line, 256, "/proc/%u/maps", pid);
	FILE *fp = fopen(line, "r");
	while(fgets(line, sizeof(line), fp) != NULL){
		strncpy(path, "[anonymous]", sizeof(path));

		int filled = sscanf(line, "%p-%*p %s %*p %*x:%*x %*u %s", &base, (char *)&perms, path);
		if(filled < 2){
			continue;
		}

		// pointer to the last character in the path
		char *end = (char *)&path[0] + strlen(path);

		char *sub = NULL;
		if(substr != NULL){
			sub = strstr(path, substr);
			if(sub == NULL){
				// substring not found
				continue;
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
				continue;
			}
		}

		// if we have no substring, get the first executable segment
		if(substr == NULL){
			if(strchr(perms, 'x') != NULL){
				found = true;
				break;
			}
		} else {
			if(strchr(perms, 's') != NULL){
				// it's a shared semgent, skip it
				continue;
			}

			// skip the matched part
			sub += sublen;
			if(sub >= end){
				// we're at the end of the path string
				// it's a full match
				found = true;
				break;
			}

			// check common version suffixes
			switch(*sub){
				case '.': //libc.
				case '-': //libc-
					found = true;
					break;
			}
		}

		if(found){
			break;
		}
	}
	fclose(fp);

	return (found) ? base : NULL;
}
