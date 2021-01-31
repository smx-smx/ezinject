#include "config.h"

#if defined(EZ_TARGET_LINUX)

#if defined(EZ_ARCH_ARM64)
#include "arch/ezinject_aarch64.h"
#elif defined(EZ_ARCH_ARM)
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

#elif defined(EZ_TARGET_FREEBSD)
#if defined(EZ_ARCH_AMD64)
#include "arch/ezinject_freebsd_amd64.h"
#elif defined(EZ_ARCH_I386)
#include "arch/ezinject_freebsd_i386.h"
#else
#error "Unsupported architecture"
#endif

#elif defined(EZ_TARGET_DARWIN)
#if defined(EZ_ARCH_AMD64)
#include "arch/ezinject_darwin_amd64.h"
#else
#error "Unsupported architecture"
#endif

#elif defined(EZ_TARGET_WINDOWS)
#if defined(EZ_ARCH_AMD64)
#include "arch/ezinject_windows_amd64.h"
#else
#error "Unsupported architecture"
#endif

#endif