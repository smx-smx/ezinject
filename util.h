#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>

#include "log.h"

void hexdump(void *pAddressIn, long lSize);
int get_stack(pid_t pid, uintptr_t *stack_start, size_t *stack_size);
void *get_base(pid_t pid, char *substr, char **ignores);
uintptr_t get_code_base(pid_t pid);
int sema_op(int sema, int idx, int op);