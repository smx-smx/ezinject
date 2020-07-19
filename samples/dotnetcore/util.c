#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <libgen.h>

char *asprintf_ex(const char *fmt, ...){
	char *str = NULL;

	va_list ap;
	va_start(ap, fmt);
	vasprintf(&str, fmt, ap);
	va_end(ap);

	return str;
}

char *basename_ex(const char *str){
	char *dup = strdup(str);
	char *base = basename(dup);
	char *cpy = strdup(base);
	free(dup);
	return cpy;
}

char *dirname_ex(const char *str){
	char *dup = strdup(str);
	char *base = dirname(dup);
	char *cpy = strdup(base);

	free(dup);
	return cpy;
}

int remove_ext(char *str){
	char *lastdot = strrchr(str, '.');
	if(lastdot == NULL){
		return -1;
	}

	*lastdot = '\0';
	return 0;
}

void *dlopen_ex(const char *libPath, int flags){
	void *existing = dlopen(libPath, RTLD_NOLOAD);
	if(existing){
		return existing;
	}
	return dlopen(libPath, flags);
}