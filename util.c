#define _GNU_SOURCE
#include "util.h"
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include "ezinject.h"

void hexdump(void *pAddressIn, long lSize) {
	char szBuf[100];
	long lIndent = 1;
	long lOutLen, lIndex, lIndex2, lOutLen2;
	long lRelPos;
	struct {
		char *pData;
		unsigned long lSize;
	} buf;
	unsigned char *pTmp, ucTmp;
	unsigned char *pAddress = (unsigned char *)pAddressIn;

	buf.pData = (char *)pAddress;
	buf.lSize = lSize;

	while (buf.lSize > 0) {
		pTmp = (unsigned char *)buf.pData;
		lOutLen = (int)buf.lSize;
		if (lOutLen > 16)
			lOutLen = 16;

		// create a 64-character formatted output line:
		sprintf(szBuf, " >                                                      %08zX", pTmp - pAddress);
		lOutLen2 = lOutLen;

		for (lIndex = 1 + lIndent, lIndex2 = 53 - 15 + lIndent, lRelPos = 0; lOutLen2; lOutLen2--, lIndex += 2, lIndex2++) {
			ucTmp = *pTmp++;
			sprintf(szBuf + lIndex, "%02X ", (unsigned short)ucTmp);
			if (!isprint(ucTmp))
				ucTmp = '.';	// nonprintable char
			szBuf[lIndex2] = ucTmp;

			if (!(++lRelPos & 3)) {	// extra blank after 4 bytes
				lIndex++;
				szBuf[lIndex + 2] = ' ';
			}
		}
		if (!(lRelPos & 3))
			lIndex--;
		szBuf[lIndex] = '<';
		szBuf[lIndex + 1] = ' ';
		printf("%s\n", szBuf);
		buf.pData += lOutLen;
		buf.lSize -= lOutLen;
	}
}

#if defined(EZ_TARGET_LINUX)
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
#elif defined(EZ_TARGET_FREEBSD)
#include <libprocstat.h>
#include <sys/sysctl.h>

void *get_base(pid_t pid, char *substr, char **ignores) {
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
	
	for (int i = 0; i < cnt; i++) {
		kve = &freep[i];
		char *path = kve->kve_path;
		base = kve->kve_start;

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
#endif