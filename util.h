#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#include "log.h"

void *get_base(pid_t pid, char *libname);
