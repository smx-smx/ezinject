/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include "ezinject_injcode.h"
#include "log.h"
#include "ezinject_module.h"

int crt_userinit(struct injcode_bearing *br){
	int result;
	result = lib_preinit(&br->user);
	if(result != 0){
		ERR("lib_preinit returned nonzero status %d, aborting...", result);
		return result;
	}

	log_set_leave_open(br->user.persist);
	result = lib_main(br->argc, br->argv);
	DBG("lib_main returned: %d", result);

	return result;
}
