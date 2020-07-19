#ifndef __UTIL_H
#define __UTIL_H

char *asprintf_ex(const char *fmt, ...);
char *basename_ex(const char *str);
char *dirname_ex(const char *str);
int remove_ext(char *str);
void *dlopen_ex(const char *libPath, int flags);

#endif