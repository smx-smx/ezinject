#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>

#include "log.h"

void hexdump(void *pAddressIn, long lSize);
void *get_base(pid_t pid, char *substr, char **ignores);
uintptr_t get_code_base(pid_t pid);
int sema_op(int sema, int idx, int op);