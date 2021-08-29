#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <signal.h>

#include "config.h"

#ifdef EZ_TARGET_WINDOWS
#include <windows.h>
#endif

#include <thread>

#ifdef EZ_TARGET_POSIX
#define EXE_SUFFIX ""
#define DIR_SEPARATOR "/"
#endif

#if defined(EZ_TARGET_WINDOWS)
#define EXE_SUFFIX ".exe"
#define LIB_SUFFIX ".dll"
#define DIR_SEPARATOR "\\"
#elif defined(EZ_TARGET_LINUX)
#define LIB_SUFFIX ".so"
#elif defined(EZ_TARGET_DARWIN)
#define LIB_SUFFIX ".dylib"
#endif

#define UNUSED(x) (void)(x)

char *asprintf_ex(const char *fmt, ...){
	char *str = NULL;

	va_list ap;
	va_start(ap, fmt);
	vasprintf(&str, fmt, ap);
	va_end(ap);

	return str;
}

typedef int (*pfnStatefulCb)(void *state, void *arg);

typedef struct {
	void *state;
	pfnStatefulCb callback;
} delegate;

int delegate_invoke(delegate *cb, void *arg){
	if(cb == NULL){
		return -1;
	}
	return cb->callback(cb->state, arg);
}

int expect(FILE *fh, char *str, int maxLines, delegate *cb){
	char line[256];
	memset(line, 0x00, sizeof(line));

	int rc = -1;

	int i;
	for(i=0;i<maxLines || maxLines < 0;i++){
		if(fgets(line, sizeof(line), fh) == NULL){
			return -1;
		}
		fputs(line, stderr);
		if(strstr(line, str) != NULL){
			rc = 0;
			if(cb != NULL){
				rc = delegate_invoke(cb, line);
			}
			break;
		}
	}

	return rc;
}

struct test_state {
	char *target;
	char *ezinject;
	char *library;
	pid_t pid;
	std::thread ezinjectRunner;
};

int run_on_pid(void *state, void *arg){
	struct test_state *ctx = (struct test_state *)state;
	char *line = (char *)arg;

	pid_t pid = 0;
	if(sscanf(line, "pid=%u", &pid) != 1){
		return -1;
	}
	ctx->pid = pid;
	return 0;
}

int run_on_return1(void *state, void *arg){
	UNUSED(arg);

	struct test_state *ctx = (struct test_state *)state;
	char *cmd = asprintf_ex("%s %u %s 1 2 3 4 5 6", ctx->ezinject, ctx->pid, ctx->library);
	ctx->ezinjectRunner = std::thread([=](){
		FILE *hCmd = popen(cmd, "r");
		free(cmd);
		char buf[255];
		while(fgets(buf, sizeof(buf), hCmd) != NULL){
			//fputs(buf, stdout);
		}
		pclose(hCmd);
	});
	return 0;
}

int run(struct test_state *ctx){
	FILE *hTarget = popen(ctx->target, "r");
	if(!hTarget){
		return -1;
	}

	delegate on_pid = {
		.state = ctx,
		.callback = run_on_pid
	};
	delegate on_return1 = {
		.state = ctx,
		.callback = run_on_return1
	};

	int rc = -1;
	do {
		if(expect(hTarget, "pid=", -1, &on_pid) != 0){
			break;
		}
		printf("[+] pid: %u""\n", ctx->pid);
		if(expect(hTarget, "return1() = 1", 8, &on_return1) != 0){
			break;
		}

		puts("[+] waiting for injection...");
		if(expect(hTarget, "[INFO] library loaded!", 40, NULL) != 0){
			break;
		}
		rc = 0;
	} while(0);

	if(ctx->pid > 0){
	#if defined(EZ_TARGET_POSIX)
		kill(ctx->pid, SIGKILL);
	#elif defined(EZ_TARGET_WINDOWS)
		HANDLE hProc = OpenProcess(SYNCHRONIZE|PROCESS_TERMINATE, FALSE, ctx->pid);
		TerminateProcess(hProc, 0);
		CloseHandle(hProc);
	#else
	#error "Unsupported platform"
	#endif
	}

	pclose(hTarget);

	if(ctx->ezinjectRunner.joinable()){
		ctx->ezinjectRunner.join();
	}

	return rc;
}

int main(int argc, char *argv[]){
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	if(argc < 4){
		fprintf(stderr, "Usage: %s [target][ezinject][library]\n", argv[0]);
		return 1;
	}

	char *target = argv[1];
	char *ezinject = argv[2];
	char *library = argv[3];
	
	struct test_state ctx;
	memset(&ctx, 0x00, sizeof(ctx));

	ctx.target = target;
	ctx.ezinject = ezinject;
	ctx.library = library;
	return run(&ctx);
}
