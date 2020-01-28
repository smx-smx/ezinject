#define _GNU_SOURCE
#include "util.h"
#include <sys/uio.h>
#include <ctype.h>

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