#include "config.h"

#if defined(EZ_ARCH_ARM)
#include "arch/ezinject_arm.h"
#elif defined(EZ_ARCH_I386)
#include "arch/ezinject_i386.h"
#elif defined(EZ_ARCH_AMD64)
#include "arch/ezinject_amd64.h"
#elif defined(EZ_ARCH_MIPS)
#include "arch/ezinject_mips.h"
#else
#error "Unsupported architecture"
#endif