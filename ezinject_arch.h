/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
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
#elif defined(EZ_ARCH_I386)
#include "arch/ezinject_windows_i386.h"
#else
#error "Unsupported architecture"
#endif

#endif
