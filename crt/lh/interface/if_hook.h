#ifndef __LH_INTERFACE_HOOK_H
#define __LH_INTERFACE_HOOK_H

#include <stdint.h>
#include "interface/hook/linux/lh_hook.h"

int unprotect(void *addr);
int inj_inject_library(const char *dllPath, int argc, char *argv[], void **out_libaddr);
void *inj_backup_function(lh_fn_hook_t *fnh, uint8_t *original_code, size_t *saved_bytes);
int inj_replace_function(lh_fn_hook_t *fnh, uintptr_t symboladdr);

#endif
