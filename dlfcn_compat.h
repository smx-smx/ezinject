/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#ifndef __DLFCN_COMPAT_H
#define __DLFCN_COMPAT_H

#include "config.h"

#if defined(EZ_TARGET_WINDOWS)
# include <Windows.h>
# define LIB_HANDLE HMODULE
# define LIB_OPEN(path) LoadLibraryA(path)
# define LIB_GETSYM(handle, sym) (void *)GetProcAddress(handle, sym)
# define LIB_CLOSE(handle) FreeLibrary(handle)
# define LIB_ERROR() "dlopen failure"
# define RTLD_LAZY 0
# define RTLD_NOW 0
# define RTLD_GLOBAL 0
// $TODO
#elif defined(EZ_TARGET_POSIX)
# include <dlfcn.h>
# define LIB_HANDLE void *
# define LIB_OPEN(path) dlopen(path, RTLD_LAZY | RTLD_GLOBAL)
# define LIB_GETSYM(handle, sym) dlsym(handle, sym)
# define LIB_CLOSE(handle) dlclose(handle)
# define LIB_ERROR() dlerror()
#else
#error "Unsupported platform"
#endif

#endif