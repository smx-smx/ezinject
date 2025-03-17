/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "config.h"

#if defined(EZ_TARGET_POSIX)
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#elif defined(EZ_TARGET_WINDOWS)
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#ifdef EZ_TARGET_DARWIN
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#endif


#include "dlfcn_compat.h"


#include "log.h"

#include "ezinject_common.h"
#include "ezinject_util.h"
#include "ezinject_injcode.h"
#include "ezinject_compat.h"

#undef MAX
#undef MIN
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

#if CMAKE_SIZEOF_VOID_P==4
#define htonp(x) htonl(x)
#define ntohp(x) ntohl(x)
#define PTRSTR "4"
#elif CMAKE_SIZEOF_VOID_P==8
#define PTRSTR "8"
#define htonp(x) ez_htonll(x)
#define ntohp(x) ez_ntohll(x)
#else
#error "Unknown pointer size"
#endif

LOG_SETUP(V_DBG);

#define WEBAPI_DEBUG

#define OP_INFO 0x49 // I
#define OP_DLOPEN 0x44 // D
#define OP_DLCLOSE 0x46 // F
#define OP_DLSYM 0x53 // S
#define OP_PEEK 0x52 // R
#define OP_POKE 0x57 // W
#define OP_CALL 0x43 // C
#define OP_QUIT 0x51 // Q

#define C_CDECL 0x43 // C
#define C_STDCALL 0x53 // S
#define C_THISCALL 0x54 // T

#ifdef EZ_TARGET_DARWIN
int fd_in = -1;
int fd_out = -1;
#endif

#ifdef EZ_TARGET_DARWIN
static int _darwin_is_sandboxed(){
	return getenv("APP_SANDBOX_CONTAINER_ID") != NULL;
}
static char *_get_home_directory(const char *username) {
    struct passwd *pw = getpwnam(username);
    if (pw == NULL) {
        PERROR("getpwnam");
        return NULL;
    }
	return pw->pw_dir;
}
#endif

/**
 *  NOTE: remember to not do unaligned writes, or it will break on ARM v4
 * https://developer.arm.com/documentation/dui0473/j/using-the-assembler/address-alignment
 **/
/**
 * NOTE: we must ensure the TCP packet is aligned to NET_IP_ALIGN bytes (2 on old Linux)
 * or it will not be dequeued from the skb (https://lwn.net/Articles/89597/)
 */
struct ez_pkt_hdr {
	uint32_t magic;
	uint32_t hdr_length;
	uint32_t body_length;
};

static void _build_pkt(struct ez_pkt_hdr *pkt, unsigned length){
	pkt->magic = htonl(0x4F4B3030); //OK00
	pkt->hdr_length = ntohl(sizeof(*pkt));
	pkt->body_length = ntohl(length);
}

intptr_t safe_send(int fd, void *buf, size_t length, int flags){
	UNUSED(flags);
	uint8_t *pb = (uint8_t *)buf;

	size_t acc = 0;
	while(acc < length){
		#ifdef EZ_TARGET_DARWIN
		ssize_t sent = write(fd_out, (void *)(&pb[acc]), length - acc);
		#else
		ssize_t sent = send(fd, (void *)(&pb[acc]), length - acc, 0);
		#endif
		if(sent < 0){
			PERROR("send");
			return -1;
		}
		acc += sent;
	}
	return (intptr_t)acc;
}

intptr_t safe_recv(int fd, void *buf, size_t length, int flags){
	UNUSED(flags);
	uint8_t *pb = (uint8_t *)buf;

	size_t acc = 0;
	while(acc < length){
		#ifdef EZ_TARGET_DARWIN
		ssize_t received = read(fd_in, (void *)(&pb[acc]), length - acc);
		#else
		ssize_t received = recv(fd, (void *)(&pb[acc]), length - acc, 0);
		#endif
		if(received < 0){
			PERROR("recv");
			return -1;
		}
		acc += received;
		DBG("remaining: %zu/%zu", acc, length);
	}
	return (intptr_t)acc;
}

intptr_t send_data(int fd, void *data, unsigned size){
	struct ez_pkt_hdr pkt;
	memset(&pkt, 0x00, sizeof(pkt));
	_build_pkt(&pkt, size);

	uint8_t *pb = (uint8_t *)&pkt;

#ifdef WEBAPI_DEBUG
	for(size_t i=0; i<sizeof(pkt); i++){
		printf("%02hhx ", pb[i]);
	}
	for(size_t i=0; i<size; i++){
		printf("%02hhx ", ((uint8_t *)data)[i]);
	}
	puts("");
#endif

	if(safe_send(fd, (void *)&pkt, sizeof(pkt), 0) != sizeof(pkt)){
		return -1;
	}
	if(safe_send(fd, data, size, 0) != size){
		return -1;
	}
	return 0;
}


intptr_t send_datahdr(int fd, unsigned size){
	struct ez_pkt_hdr pkt;
	memset(&pkt, 0x00, sizeof(pkt));
	_build_pkt(&pkt, size);

#ifdef EZ_TARGET_DARWIN
	if(write(fd_out, (void *)&pkt, sizeof(pkt)) != sizeof(pkt)){
		return -1;
	}
#else
	if(send(fd, (void *)&pkt, sizeof(pkt), 0) != sizeof(pkt)){
		return -1;
	}
#endif
	return 0;
}

static inline intptr_t send_str(int fd, char *str){
	return send_data(fd, (uint8_t *)str, str ? strlen(str) : 0);
}

static inline intptr_t send_ptrval(int fd, void *ptr){
	uintptr_t val = (uintptr_t)htonp((uintptr_t)ptr);
	return send_data(fd, (uint8_t *)&val, sizeof(val));
}

void *read_ptr(uint8_t **ppData){
	uint8_t *data = *ppData;

	uintptr_t val = 0;
	memcpy(&val, data, sizeof(val));
	val = ntohp(val);

	*ppData += sizeof(val);
	return (void *)val;
}

int handle_client(int client){
#ifndef EZ_TARGET_DARWIN
	/** disable NAGLE algorithm (packet aggregation) **/
	int flag = 1;
	setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
#endif

	int last_txrx = 0;

	#define SAFE_SEND(fd, buf, length, flags) do { \
		last_txrx = safe_send(fd, buf, length, flags); \
		if(last_txrx < 0) { \
			PERROR("send"); \
			serve = 0; break; \
		} \
	} while(0)

	#define SAFE_RECV(fd, buf, length, flags) do { \
		last_txrx = safe_recv(fd, buf, length, flags); \
		if(last_txrx < 0) { \
			PERROR("recv"); \
			serve = 0; break; \
			break; \
		} \
	} while(0)

	int serve = 1;
	while(serve){
		unsigned int length = 0;
		SAFE_RECV(client, &length, sizeof(length), 0);
		length = ntohl(length);
		size_t malloc_sz = (size_t)WORDALIGN(MAX(length, 64));
		DBG("incoming msg, length: %u", length);
		uint8_t *mem = calloc(malloc_sz, 1);
		uint8_t *data = mem;
		SAFE_RECV(client, data, length, 0);

		// prefer ptr-sized op, or all future accesses will be unaligned
		uint32_t op = (uint32_t)(uintptr_t)read_ptr(&data);
		DBG("cmd: %x", op);
		switch(op){
			case OP_INFO:{
				DBG("OP_INFO");
				#if defined(EZ_TARGET_DARWIN)
				send_str(client, "darwin"PTRSTR);
				#elif defined(EZ_TARGET_POSIX)
				send_str(client, "posix"PTRSTR);
				#elif defined(EZ_TARGET_WINDOWS)
				send_str(client, "win32"PTRSTR);
				#else
				#error "Unsupported build type"
				#endif
				break;
			}
			case OP_DLOPEN:{
				DBG("OP_DLOPEN");
				const char *path = (const char *)data;
				void *handle = NULL;
				if(*path == '\0'){
					DBG("dlopen(NULL)");
				#if defined(EZ_TARGET_POSIX)
					handle = dlopen(NULL, RTLD_NOW);
				#elif defined(EZ_TARGET_WINDOWS)
					handle = GetModuleHandle(NULL);
				#endif
				} else {
					DBG("dlopen(%s)", path);
					handle = LIB_OPEN(path);
				}
				if(send_ptrval(client, handle) != 0){
					ERR("send_ptrval failed");
					serve = 0;
				}
				break;
			}
			case OP_DLSYM:{
				DBG("OP_DLSYM");
				void *handle = read_ptr(&data);
				char *sym_name = (char *)data;
				DBG("dlsym(%p, %s)", handle, sym_name);
				void *sym = LIB_GETSYM(handle, sym_name);
				if(send_ptrval(client, sym) != 0){
					ERR("send_ptrval failed");
					serve = 0;
				}
				break;
			}
			case OP_DLCLOSE:{
				DBG("OP_DLCLOSE");
				void *handle = read_ptr(&data);
				LIB_CLOSE(handle);
				if(send_str(client, NULL) != 0){
					ERR("send_str failed");
					serve = 0;
				}
				break;
			}
			case OP_PEEK:{
				DBG("OP_PEEK");
				uint8_t *start_addr = read_ptr(&data);
				size_t length = (size_t)read_ptr(&data);
				DBG("length: %zu", length);

				int blocksize = 4096;
				int nblocks = length / blocksize;
				int blockoff = length % blocksize;

				// align to multiple of NETALIGN (2)
				int rem = (length % sizeof(uintptr_t));
				uintptr_t padding = 0;

				int length_aligned = ntohl(length + rem);

				if(send_datahdr(client, length_aligned) != 0){
					ERR("send_datahdr failed");
					serve = 0;
					break;
				}

				DBG("writing %d blocks", nblocks);
				for(int i=0; i<nblocks; i++){
					SAFE_SEND(client, start_addr, blocksize, 0);
					start_addr += blocksize;
				}
				DBG("writing %d bytes", blockoff);
				if(blockoff > 0){
					SAFE_SEND(client, start_addr, blockoff, 0);
				}

				if(rem > 0){
					DBG("writing rem: %d", rem);
					SAFE_SEND(client, &padding, rem, 0);
				}
				break;
			}
			case OP_POKE:{
				DBG("OP_POKE");
				uint8_t *start_addr = read_ptr(&data);
				size_t length = (size_t)read_ptr(&data);
				DBG("size: %zu", length);

				int blocksize = 4096;
				int nblocks = length / blocksize;
				int blockoff = length % blocksize;

				DBG("reading %d blocks", nblocks);
				for(int i=0; i<nblocks; i++){
					SAFE_RECV(client, start_addr, blocksize, 0);
					start_addr += blocksize;
				}
				DBG("reading %d bytes", blockoff);
				if(blockoff > 0){
					SAFE_RECV(client, start_addr, blockoff, 0);
				}

				if(send_str(client, NULL) != 0){
					ERR("send_str failed");
					serve = 0;
				}

				break;
			}
			case OP_CALL:{
				DBG("OP_CALL");
				uint8_t call_type = *(data++);
				size_t nargs = (size_t)read_ptr(&data);
				void *addr = read_ptr(&data);

				if(nargs > 14) break;

				void *a[15] = {NULL};
				for(size_t i=0; i<nargs; i++){
					a[i] = read_ptr(&data);
					DBGPTR(a[i]);
				}

				void *result = NULL;

				switch(call_type){
					case C_CDECL:
						switch(nargs){
							#include "calls.c"
						}
						break;
					case C_STDCALL:
						break;
					case C_THISCALL:
						break;
				}

				if(send_ptrval(client, result) != 0){
					ERR("send_ptrval failed");
					serve = 0;
				}
				break;
			}
			case OP_QUIT:{
				if(send_str(client, NULL) != 0){
					ERR("send_str failed");
				}
				serve = 0;
				break;
			}
			default:
				ERR("Unhandled command %x received", op);
				break;
		}

		free(mem);
	}
#ifndef EZ_TARGET_DARWIN
	close(client);
#endif
	return 0;
}

void *start_server(void *arg){
#ifdef EZ_TARGET_DARWIN
	int rc = -1;

	char *fifo_path_in = NULL;
	char *fifo_path_out = NULL;

	do {
		//char *home = getenv("HOME");
		const char *user = getenv("USER");
		if(!user){
			fputs("USER environment variable not set\n", stderr);
			break;
		}
		const char *home = _get_home_directory(user);
		if(!home){
			fputs("Cannot determine HOME directory\n", stderr);
			break;
		}

		pid_t pid = getpid();

		asprintf(&fifo_path_in, "%s/.Trash/netsock.%d", home, pid);
		asprintf(&fifo_path_out, "%s/.Trash/netsock.%d", home, pid);

		if (access(fifo_path_in, F_OK) == -1) {
			INFO("creating FIFO-IN: %s", fifo_path_in);
			if ((rc=mkfifo(fifo_path_in, 0666)) < 0) {
				free(fifo_path_in);
				PERROR("mkfifo");
				break;
			}
		}

		if (access(fifo_path_out, F_OK) == -1){
			INFO("creating FIFO-OUT: %s", fifo_path_out);
			if ((rc=mkfifo(fifo_path_out, 0666)) < 0) {
				free(fifo_path_in);
				free(fifo_path_out);
				PERROR("mkfifo");
				break;
			}
		}

		INFO("opening FIFO-OUT: %s", fifo_path_out);
		fd_out = open(fifo_path_out, O_WRONLY);
		if(fd_out < 0){
			PERROR("open");
			free(fifo_path_in);
			free(fifo_path_out);
			break;
		}

		INFO("opening FIFO-IN: %s", fifo_path_in);
		fd_in = open(fifo_path_in, O_RDONLY);
		if(fd_in < 0){
			PERROR("open");
			free(fifo_path_in);
			free(fifo_path_out);
			break;
		}
		free(fifo_path_in);
		free(fifo_path_out);
	} while(0);

	if(fd_in > -1 && fd_out > -1){
		int run = 1;
		while(run){
			handle_client(0);
		}
		close(fd_in);
		close(fd_out);
	}

	return (void *)(uintptr_t)rc;
#else
	unsigned short port = (unsigned short)(uintptr_t)arg;
	int rc = 0;
	do {
		int sock = socket(AF_INET, SOCK_STREAM, 0);
		if(sock < 0){
			perror("socket");
			rc = -1;
			break;
		}

		struct sockaddr_in sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_ANY),
			.sin_port = htons(port)
		};
		int enable = 1;
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&enable, sizeof(int)) < 0){
    		perror("setsockopt(SO_REUSEADDR)");
		}
		if(bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0){
			perror("bind");
			rc = -1;
			break;
		}

		if(listen(sock, 5) < 0){
			perror("listen");
			rc = -1;
			break;
		}

		int run = 1;
		while(run){
			struct sockaddr_in sac;
			socklen_t saclen = sizeof(sac);
			int client = accept(sock, (struct sockaddr *)&sac, &saclen);
			if(client < 0){
				perror("accept");
			}
			/*int result =*/ handle_client(client);
		}
	} while(0);

	return (void *)(uintptr_t)rc;
#endif
}

int lib_preinit(struct injcode_user *user){
	user->persist = 1;
	return 0;
}

int lib_main(int argc, char *argv[]){
	lputs("Hello World from main");
	for(int i=0; i<argc; i++){
		lprintf("argv[%d] = %s\n", i, argv[i]);
	}

	if(argc < 2){
		lprintf("usage: %s [port]\n", argv[0]);
		return 1;
	}

	uintptr_t port = strtoul(argv[1], NULL, 10);
	pthread_t tid;
	pthread_create(&tid, NULL, start_server, (void *)port);
	pthread_detach(tid);
	return 0;
}
