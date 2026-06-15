#ifndef __EZINJECT_CTX_PLATFORM_FREEBSD_H
#define __EZINJECT_CTX_PLATFORM_FREEBSD_H

struct ctx_platform {
	uint8_t *saved_sc_data;
	ssize_t saved_sc_size;
	int force_mmap_syscall;
};

#endif
