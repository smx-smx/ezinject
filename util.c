#define _GNU_SOURCE
#include "util.h"
#include <sys/uio.h>

void *get_base(pid_t pid, char *libname)
{
	char line[256];
	char path[128];
	void *base;
	bool found = false;
	snprintf(line, 256, "/proc/%u/maps", pid);
	FILE *fp = fopen(line, "r");
	int val;
	do
	{
		if(!fgets(line, 256, fp))
			break;
		strcpy(path, "[anonymous]");
		val = sscanf(line, "%p-%*p %*s %*p %*x:%*x %*u %s", &base, path);
		if(!libname || strstr(path, libname))
			found = true;
	} while(val > 0 && !found);
	fclose(fp);
	return base;
}

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
