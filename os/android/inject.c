#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>

#include "ezinject.h"
#include "log.h"

#define SOCKNAME "/dev/shm/%08x"
#define SUN_PATH_ABSTRACT(ptr) ((char *)(ptr) + offsetof(struct sockaddr_un, sun_path) + 1)

#ifndef __NR_mmap
#define __NR_mmap __NR_mmap2
#endif

static char *asun_build_path(key_t key){
	struct sockaddr_un dummy;
	int max_length = sizeof(dummy.sun_path) - 1;
	char *buf = calloc(max_length, 1);
	snprintf(buf, max_length, SOCKNAME, key);
	return buf;
}

static int asun_path_cpy(char *dest, const char *src){
	struct sockaddr_un dummy;
	int in_length = strlen(src) + 1;
	int max_length = sizeof(dummy.sun_path) - 1;

	int length = in_length;
	if(in_length > max_length){
		length = max_length;
	}

	strncpy(dest, src, length);
	return length;
}

struct shmat_payload {
	struct sockaddr_un sock;
	key_t key;

	char body;
	struct iovec msgdata;
	struct msghdr msghdr;

	struct {
		struct cmsghdr h;
		int fd;
	} cmsg;
};

uintptr_t prepare_socket_payload(ez_addr payload){
	struct shmat_payload *pl = (struct shmat_payload *)payload.local;
	
	// prepare message data (dummy, single char)
	struct iovec iovec = {
		.iov_len = sizeof(pl->body),
		.iov_base = (void *)EZ_REMOTE(payload, &pl->body)
	};
	pl->msgdata = iovec;

	// attach message data and control data to header
	struct msghdr msghdr = {
		.msg_name = NULL,
		.msg_namelen = 0,
		// message data
		.msg_iov = (void *)EZ_REMOTE(payload, &pl->msgdata),
		.msg_iovlen = 1,
		.msg_flags = 0,
		// control data
		.msg_control = (void *)EZ_REMOTE(payload, &pl->cmsg),
		.msg_controllen = sizeof(pl->cmsg)
	};
	pl->msghdr = msghdr;

	// prepare control header
	struct cmsghdr chdr = {
		.cmsg_len = pl->msghdr.msg_controllen,
		.cmsg_level = SOL_SOCKET,
		.cmsg_type = SCM_RIGHTS
	};
	pl->cmsg.h = chdr;

	// set initial control data
	pl->cmsg.fd = -1; // set initial fd value

	// return remote control data address
	return UPTR(pl->msghdr.msg_control) + sizeof(struct cmsghdr);
}

uintptr_t remote_pl_alloc(struct ezinj_ctx *ctx, size_t map_size){
	uintptr_t result = (uintptr_t)NULL;

	key_t shm_key = (key_t)ctx->target;

	struct shmat_payload payload;
	memset(&payload, 0x00, sizeof(payload));
	
	/* setup socket parameters */
	payload.sock.sun_family = AF_UNIX;
	char *socketPath = asun_build_path(shm_key);
	DBG("socket path: %s", socketPath);
	asun_path_cpy(SUN_PATH_ABSTRACT(&payload.sock), socketPath);
	free(socketPath);
	payload.key = shm_key;

	regs_t orig_regs;
	regs_t regs;
	remote_getregs(ctx, &regs);
	memcpy(&orig_regs, &regs, sizeof(regs));

	uintptr_t remote_stack = REG(regs, REG_SP);

	size_t payload_size = 0;
	#if defined(EZ_ARCH_ARM64) || defined(EZ_ARCH_AMD64)
	payload_size = (size_t) ALIGN(sizeof(payload), 16);
	#else
	payload_size = (size_t) WORDALIGN(sizeof(payload));
	#endif
	DBG("stack payload_size: %zu", payload_size);

	uintptr_t r_payload = remote_stack - payload_size;

	uint8_t *backup = calloc(payload_size, 1);
	do {
		INFO("backing up stack...");
		if(remote_read(ctx, backup, r_payload, payload_size) != payload_size){
			ERR("stack backup failed");
			break;
		}

		DBG("remote stack: %p", (void *)remote_stack);
		DBG("remote payload: %p", (void *)r_payload);

		ez_addr payload_addr = {
			.local = UPTR(&payload),
			.remote = r_payload
		};
		
		// socket message control data
		uintptr_t r_sock_cdata = prepare_socket_payload(payload_addr);
		DBG("remote cdata: %p", (void *)r_sock_cdata);

		remote_write(ctx, r_payload, &payload, payload_size);

		REG(regs, REG_SP) = r_payload;
		remote_setregs(ctx, &regs);

		int remote_sock_fd = (int)RSCALL3(ctx, __NR_socket, AF_UNIX, SOCK_STREAM, 0);
		if(remote_sock_fd < 0){
			ERR("cannot create UNIX socket");
			break;
		}
		DBG("remote socket(): %d", remote_sock_fd);

		do {
			int ret = -1;
			uintptr_t r_sockaddr = r_payload + offsetof(struct shmat_payload, sock);
			ret = (int)RSCALL3(ctx, __NR_connect, remote_sock_fd, r_sockaddr, sizeof(payload.sock));
			DBG("remote connect(): %d", ret);
			if(ret != 0){
				ERR("cannot connect to UNIX socket");
				break;
			}

			uintptr_t r_key = r_payload + offsetof(struct shmat_payload, key);
			ret = (int) RSCALL6(ctx, __NR_sendto, remote_sock_fd, r_key, sizeof(payload.key), 0, NULL, 0);
			DBG("remote send(): %d", ret);
			if(ret != sizeof(payload.key)){
				ERR("send() failed");
				break;
			}

			char cmd[256];
			sprintf(cmd, "ls -als /proc/%u/fd", ctx->target);
			system(cmd);

			uintptr_t r_msghdr = r_payload + offsetof(struct shmat_payload, msghdr);
			ret = (int)RSCALL3(ctx, __NR_recvmsg, remote_sock_fd, r_msghdr, 0);
			DBG("remote recvmsg(): %d", ret);
			if(ret < 0){
				ERR("recvmsg() failed");
				break;
			}

			uintptr_t l_remote_fd;
			// read remote fd
			remote_read(ctx, &l_remote_fd, r_sock_cdata, sizeof(uintptr_t));

			sprintf(cmd, "ls -als /proc/%u/fd", ctx->target);
			system(cmd);

			int remote_fd = (int)l_remote_fd;
			DBG("remote fd: %d", remote_fd);
			if(remote_fd < 0){
				ERR("invalid ashmem fd");
				break;
			}

			uintptr_t r_mem = RSCALL6(ctx, __NR_mmap,
				0, map_size,
				PROT_READ|PROT_WRITE|PROT_EXEC,
				MAP_SHARED,
				remote_fd, 0
			);
			DBG("remote mmap: %p", (void *)r_mem);
			if(r_mem == (uintptr_t)MAP_FAILED){
				ERR("mmap failed");
				break;
			}

			result = r_mem;
		} while(0);
		RSCALL1(ctx, __NR_close, remote_sock_fd);
	} while(0);

	INFO("restoring stack");
	remote_write(ctx, r_payload, backup, payload_size);
	remote_setregs(ctx, &orig_regs);
	free(backup);

	return result;
}

EZAPI remote_pl_free(struct ezinj_ctx *ctx, uintptr_t remote_shmaddr){
	UNUSED(ctx);
	UNUSED(remote_shmaddr);
	return 0;
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