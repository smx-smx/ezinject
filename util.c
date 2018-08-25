#include "util.h"

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
