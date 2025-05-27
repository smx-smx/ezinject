/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <stdbool.h>
#include <string.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <libprocstat.h>

#include "ezinject.h"

EZAPI os_api_init(struct ezinj_ctx *ctx){
	return 0;
}

void *get_base(struct ezinj_ctx *ctx, pid_t pid, char *substr, char **ignores) {
	struct kinfo_vmentry *freep, *kve;
	unsigned int cnt;

	struct procstat *procstat = procstat_open_sysctl();

	unsigned int nprocs;
	struct kinfo_proc *kipp = procstat_getprocs(procstat, KERN_PROC_PID, pid, &nprocs);
	freep = procstat_getvmmap(procstat, kipp, &cnt);
	if (freep == NULL){
		procstat_freeprocs(procstat, kipp);
		procstat_close(procstat);
		return NULL;
	}

	bool found = false;
	int sublen = 0;
	if(substr != NULL){
		sublen = strlen(substr);
	}

	void *base = NULL;

	for (unsigned int i = 0; i < cnt; i++) {
		kve = &freep[i];
		char *path = kve->kve_path;
		base = (void *)kve->kve_start;

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
			if(kve->kve_protection & KVME_PROT_EXEC){
				found = true;
				break;
			}
		} else {
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

	procstat_freeprocs(procstat, kipp);
	procstat_close(procstat);
	return (found) ? base : NULL;
}
