#define _GNU_SOURCE
#include "util.h"
#include <stdbool.h>
#include <string.h>
#include <sys/uio.h>
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

void *get_base(pid_t pid, char *libname)
{
	char line[256];
	char path[128];
	void *base;
	char perms[8];
	bool found = false;
	snprintf(line, 256, "/proc/%u/maps", pid);
	FILE *fp = fopen(line, "r");
	int val;
	do
	{
		if(!fgets(line, 256, fp))
			break;
		strcpy(path, "[anonymous]");
		val = sscanf(line, "%p-%*p %s %*p %*x:%*x %*u %s", &base, (char *)&perms, path);
		
		if(strstr(path, libname) && strchr(perms, 'x') != NULL){
			found = true;
		}
	} while(val > 0 && !found);
	fclose(fp);
	return base;
}

size_t find_adj_bytes(FILE *src, size_t sz, unsigned char ch, size_t nmemb){
	size_t i;
	int fch;
	do {
		for(i=0; i < sz && (fch=fgetc(src)) == ch; i++);
	} while(i < sz && fch != EOF && i != nmemb);

	DBG("cnt[%02X] => %zu", ch, i);
	return i;
}

FILE *mem_open(pid_t pid){
	char line[256];
	snprintf(line, sizeof(line), "/proc/%u/mem", pid);
	return fopen(line, "rb+");
}

uintptr_t find_cave(pid_t pid, FILE *hmem, size_t dataLength){
	char line[256];

	snprintf(line, sizeof(line), "/proc/%u/maps", pid);
	FILE *fp = fopen(line, "r");
	if(fp == NULL){
		PERROR("fopen maps");
		return 0;
	}

	uintptr_t start, end;
	char perms[8];
	memset(perms, 0x00, sizeof(perms));

	int val;
	uintptr_t cave_addr = 0;
	while(cave_addr == 0){
		if(!fgets(line, sizeof(line), fp)){
			PERROR("fgets");
			break;			
		}
		val = sscanf(line, "%p-%p %s %*p %*x:%*x %*u %*s", (void **)&start, (void **)&end, (char *)&perms);
		if(val == 0){
			break;
		}

		if(strchr(perms, 'x') != NULL){
			size_t mem_length = end - start;

			INFO("Scanning cave: %p - %p", (void *)start, (void *)end);

			if(fseek(hmem, start, SEEK_SET) != 0){
				INFO("unreadable");
				continue;
			}

			size_t cave_size = 0;
			long int mempos;
			do {
				cave_size = find_adj_bytes(hmem, mem_length, 0x00, dataLength);
				mempos = ftell(hmem);
			} while(
				cave_size < dataLength &&
				mempos > -1 &&
				(uintptr_t)mempos < end
			);

			if(cave_size >= dataLength){
				INFO("Cave found (size:%zu)", cave_size);
				if(fseek(hmem, -cave_size, SEEK_CUR) != 0){
					PERROR("fseek");
					break;
				}
				cave_addr = ftell(hmem);

#if defined(EZ_ARCH_ARM) || defined(EZ_ARCH_MIPS)
				uintptr_t cave_addr_aligned = (uintptr_t)MEMALIGN(cave_addr);
				// check if we're word aligned
				int rem = cave_addr_aligned - cave_addr;
				if(rem != 0 && cave_size > 0){
					if((cave_size - rem) < dataLength){
						// no room to remove 1 byte, continue searching
						cave_addr = 0;
					} else {
						cave_size -= rem;
						cave_addr += rem;
					}
				}
#endif
			}
		}
	}

	fclose(fp);

	return cave_addr;
}

#if 0
ssize_t memcpy_to(pid_t pid, void *remote_dest, void* local_src, size_t n)
{
	struct iovec local_iov = {.iov_base = local_src, .iov_len = n};
	struct iovec remote_iov = {.iov_base = remote_dest, .iov_len = n};

	return process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
}

ssize_t memcpy_from(pid_t pid, void *local_dest, void* remote_src, size_t n)
{
	struct iovec local_iov = {.iov_base = local_dest, .iov_len = n};
	struct iovec remote_iov = {.iov_base = remote_src, .iov_len = n};

	return process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
}
#endif