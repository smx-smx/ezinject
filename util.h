#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#include "log.h"

void *get_base(pid_t pid, char *libname);
ssize_t memcpy_to(pid_t pid, void *remote_dest, void* local_src, size_t n);
ssize_t memcpy_from(pid_t pid, void *local_dest, void* remote_src, size_t n);
