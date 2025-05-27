/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/syslimits.h>
#include <mach-o/dyld_images.h>

#include "ezinject.h"
#include "ezinject_common.h"
#include "log.h"

EZAPI os_api_init(struct ezinj_ctx *ctx){
	return 0;
}

void *get_base(struct ezinj_ctx *ctx, pid_t pid, char *substr, char **ignores) {
	UNUSED(ignores);

	mach_port_t task;
	if(pid == getpid()){
		task = mach_task_self();
	} else if(pid == ctx->target) {
		task = ctx->task;
	} else {
		ERR("invalid pid specified");
		return NULL;
	}

	struct task_dyld_info dyld_info;
	mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
	kern_return_t kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
	if(kr != KERN_SUCCESS){
		ERR("TASK_DYLD_INFO failed");
		return NULL;
	}

	
	struct dyld_all_image_infos infos;
	memset(&infos, 0x00, sizeof(infos));

	if(remote_read(ctx, &infos, dyld_info.all_image_info_addr, sizeof(infos)) != sizeof(infos)){
		ERR("remote_read failed for dyld_all_image_infos");
		return NULL;
	}

	DBG("number of images: %u", infos.infoArrayCount);
	size_t infoArraySize = sizeof(struct dyld_image_info) * infos.infoArrayCount;
	struct dyld_image_info *image_array = calloc(infos.infoArrayCount, sizeof(struct dyld_image_info));;
	
	void *res = NULL;
	do {
		if(remote_read(ctx, image_array, (uintptr_t)infos.infoArray, infoArraySize) != infoArraySize){
			ERR("remote_read failed for infoArray");
			break;
		}

		static const int chunk_size = 64;
		for (uint32_t i = 0; i < infos.infoArrayCount; i++) {
			struct dyld_image_info image = image_array[i];
			char path_buffer[256] = {0};
			bool found_term = false;
			for(int offset = 0; !found_term ;offset += chunk_size){
				intptr_t nRead = 0;
				if((nRead=remote_read(ctx, &path_buffer[offset], (uintptr_t)image.imageFilePath + offset, chunk_size)) < 1){
					path_buffer[offset + nRead] = '\0';
					break;
				} else {
					for(int j=0; j<chunk_size; j++){
						if(path_buffer[offset + j] == '\0'){
							found_term = true;
							break;
						}
					}
				}
			}
			if(!found_term){
				ERR("remote_read failed for image.imageFilePath");
				continue;
			}

			if(substr == NULL || strstr(path_buffer, substr) != NULL){
				res = (void *)image.imageLoadAddress;
				break;
			}
		}
	} while(0);
	
	free(image_array);
	return res;
}
