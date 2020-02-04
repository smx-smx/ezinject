#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>

#include "log.h"

void hexdump(void *pAddressIn, long lSize);
void *get_base(pid_t pid, char *substr, char **ignores);
size_t find_adj_bytes(FILE *src, size_t sz, unsigned char ch, size_t nmemb);
FILE *mem_open(pid_t pid);
uintptr_t find_cave(pid_t pid, FILE *hmem, size_t dataLength);
uintptr_t get_code_base(pid_t pid);

#if 0
ssize_t memcpy_to(pid_t pid, void *remote_dest, void* local_src, size_t n);
ssize_t memcpy_from(pid_t pid, void *local_dest, void* remote_src, size_t n);
#endif