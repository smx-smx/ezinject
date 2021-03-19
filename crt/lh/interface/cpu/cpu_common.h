#ifndef __LH_CPU_COMMON_H
#define __LH_CPU_COMMON_H

#define WRITE(ptr, t, v) \
	do { \
		*(t *)(ptr) = v; \
		ptr = (uint8_t *)(ptr) + sizeof(t); \
	} while(0)

#define WRITE8(ptr, v) WRITE(ptr, uint8_t, v)
#define WRITE16(ptr, v) WRITE(ptr, uint16_t, v)
#define WRITE32(ptr, v) WRITE(ptr, uint32_t, v)

#endif