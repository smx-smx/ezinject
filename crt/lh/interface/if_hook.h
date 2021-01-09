#ifndef __LH_INTERFACE_HOOK_H
#define __LH_INTERFACE_HOOK_H

#include <stddef.h>
#include <stdint.h>

#define LHM_FN_COPY_BYTES 16

int unprotect(void *addr);
int inj_inject_library(const char *dllPath, int argc, char *argv[], void **out_libaddr);
void *inj_backup_function(void *original_code, size_t *num_saved_bytes, int opcode_bytes_to_restore);
int inj_replace_function(void *original_fn, void *replacement_fn);

#endif
