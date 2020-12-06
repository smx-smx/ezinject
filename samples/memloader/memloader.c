#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <unistd.h>
#include "ezinject_injcode.h"
#include "log.h"

LOG_SETUP(V_DBG);

extern void blob_start();
extern void blob_end();

static struct injcode_user *gUser;

int lib_preinit(struct injcode_user *user){
	gUser = user;
	return 0;
}

int lib_main(int argc, char *argv[]){
	int fd = syscall(__NR_memfd_create, "", 0);
	if(fd < 0){
		perror("memfd_create");
		return 1;
	}

	write(fd, blob_start, PTRDIFF(blob_end, blob_start));
	lseek(fd, 0, SEEK_SET);

	char *fdPath;
	asprintf(&fdPath, "/proc/self/fd/%d", fd);

	void *handle = dlopen(fdPath, RTLD_NOW | RTLD_GLOBAL);
	free(fdPath);
	if(handle == NULL){
		printf("dlopen() failed: %s\n", dlerror());
		close(fd);
		return 1;
	}

	int rc = 1;
	do {
		int (*pfnPreinit)(struct injcode_user *user) = dlsym(handle, "lib_preinit");
		int (*pfnMain)(int, char **) = dlsym(handle, "lib_main");

		if(pfnPreinit == NULL || pfnMain == NULL){
			break;
		}

		if((rc=pfnPreinit(gUser)) != 0){
			printf("lib_preinit returned nonzero result %d, aborting\n", rc);
			break;
		}
		rc = pfnMain(argc, argv);
	} while(0);

	if(!gUser->persist){
		dlclose(handle);
		close(fd);
	}

	return rc;
}