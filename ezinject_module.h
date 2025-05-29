/*
 * Copyright (C) 2025 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#ifndef __EZINJECT_MODULE_H
#define __EZINJECT_MODULE_H

#include "config.h"
#include "ezinject_compat.h"
#include "ezinject_injcode.h"
#include "dlfcn_compat.h"
#include "log.h"

#ifdef USE_LH
#include "interface/if_hook.h"
#endif

extern int lib_loginit(log_config_t *log_cfg);
extern int lib_preinit(struct injcode_user *user);
extern int lib_main(int argc, char *argv[]);
DLLEXPORT extern int crt_init(struct injcode_bearing *br);
#endif