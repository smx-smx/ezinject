#include "config.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ptrace.h>

#include "ezinject_compat.h"
#include "ezinject.h"

#include "log.h"

uintptr_t remote_pl_alloc(struct ezinj_ctx *ctx, size_t mapping_size){
	uintptr_t result = RSCALL6(ctx, __NR_mmap2,
		NULL, mapping_size,
		PROT_READ | PROT_WRITE | PROT_EXEC,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
	);
	if(result == (uintptr_t)MAP_FAILED){
		return 0;
	}
	return result;
}

static EZAPI _export_pl(struct ezinj_ctx *ctx){
	unlink(PL_FILEPATH);
	int fd = open(PL_FILEPATH, O_WRONLY | O_SYNC | O_CREAT, (mode_t)0666);
	if(fd <= 0){
		PERROR("open");
		return -1;
	}

	struct injcode_bearing *br = (struct injcode_bearing *)ctx->mapped_mem.local;
	if(write(fd, ctx->mapped_mem.local, br->mapping_size) != br->mapping_size){
		PERROR("write");
		return -1;
	}

	close(fd);

	return 0;
}

EZAPI remote_pl_copy(struct ezinj_ctx *ctx){
	struct injcode_bearing *br = (struct injcode_bearing *)ctx->mapped_mem.local;
	uintptr_t br_remote = PL_REMOTE(ctx, br);

	uintptr_t r_remote_filepath = br_remote + offsetof(struct injcode_bearing, pl_filepath);
	size_t filepath_size = WORDALIGN(sizeof(br->pl_filepath));

	// write pl_filepath only
	if(remote_write(ctx, r_remote_filepath, br->pl_filepath, filepath_size) != filepath_size){
		ERR("remote_write: failed to write pl_filepath");
		return -1;
	}

	// write payload to file
	if(_export_pl(ctx) != 0){
		ERR("_export_pl failed");
		return -1;
	}

	intptr_t rc = -1;
	do {
		int r_fd = RSCALL2(ctx, __NR_open, r_remote_filepath, O_RDONLY);
		if(r_fd <= 0){
			ERR("remote open(2) failed");
			break;
		}
		DBG("remote fd: %d", r_fd);

		if(RSCALL3(ctx, __NR_read, r_fd, ctx->mapped_mem.remote, br->mapping_size) != br->mapping_size){
			ERR("remote read(2) failed");
			break;
		}

		if(RSCALL1(ctx, __NR_close, r_fd) < 0){
			ERR("remote close(2) failed");
			break;
		}
		rc = 0;
	} while(0);

	unlink(PL_FILEPATH);
	return rc;
}

EZAPI remote_pl_free(struct ezinj_ctx *ctx, uintptr_t remote_shmaddr){
	struct injcode_bearing *br = (struct injcode_bearing *)ctx->mapped_mem.local;
	return (intptr_t) CHECK(RSCALL2(ctx, __NR_munmap, ctx->mapped_mem.remote, br->mapping_size));
}

EZAPI remote_sc_check(struct ezinj_ctx *ctx){
	pid_t remote_pid = (pid_t)RSCALL0(ctx, __NR_getpid);
	if(remote_pid != ctx->target){
		ERR("Remote syscall returned incorrect result!");
		ERR("Expected: %u, actual: %u", ctx->target, remote_pid);
		return -1;
	}
	return 0;
}