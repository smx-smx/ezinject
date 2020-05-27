#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>

#include "log.h"

void hexdump(void *pAddressIn, long lSize);
int get_stack(pid_t pid, uintptr_t *stack_start, size_t *stack_size);
void *get_base(pid_t pid, char *substr, char **ignores);
uintptr_t get_code_base(pid_t pid);

#if 0
ssize_t memcpy_to(pid_t pid, void *remote_dest, void* local_src, size_t n);
ssize_t memcpy_from(pid_t pid, void *local_dest, void* remote_src, size_t n);
#endif