/*
 * Copyright (C) 2021 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */

/*#define PL_RETURN(sc, x) do { \
	((sc)->result = (x)); \
	sc->libc_syscall(__NR_kill, \
		sc->libc_syscall(__NR_getpid), \
		SIGSTOP \
	); \
	while(1); \
} while(0)
*/

#define PL_RETURN(sc, x) return (x)

intptr_t SCAPI injected_sc6(volatile struct injcode_call *sc){
	return sc->libc_syscall(
		sc->argv[0], sc->argv[1],
		sc->argv[2], sc->argv[3],
		sc->argv[4], sc->argv[5],
		sc->argv[6]
	);
}

INLINE void inj_thread_stop(struct injcode_ctx *ctx, int signal){
	// awake ptrace
	// success: SIGSTOP
	// failure: anything else
	struct injcode_bearing *br = ctx->br;
	br->libc_syscall(__NR_kill, br->libc_syscall(__NR_getpid), signal);
	while(1);
}

INLINE void *inj_dlopen(struct injcode_ctx *ctx, const char *filename, unsigned flags){
	return ctx->libdl.dlopen(filename, flags);
}

INLINE void inj_thread_init(
	struct injcode_bearing *br,
	struct thread_api *api
){
	api->pthread_mutex_init(&br->mutex, 0);
	api->pthread_cond_init(&br->cond, 0);
}

INLINE intptr_t inj_thread_wait(
	struct injcode_ctx *ctx,
	intptr_t *pExitStatus
){
	struct injcode_bearing *br = ctx->br;
	struct thread_api *api = &ctx->libthread;

	// wait for user thread to die
	PCALL(ctx, inj_dchar, 'j');

	api->pthread_mutex_lock(&br->mutex);
	while(!br->loaded_signal){
		api->pthread_cond_wait(&br->cond, &br->mutex);
	}
	api->pthread_mutex_unlock(&br->mutex);

	*pExitStatus = br->thread_exit_code;
	return 0;
}

INLINE intptr_t _inj_init_libdl(struct injcode_ctx *ctx){
	PCALL(ctx, inj_puts, ctx->libdl_name);

	// just to make sure it's really loaded
	ctx->h_libdl = ctx->libdl.dlopen(ctx->libdl_name, RTLD_NOLOAD);
	PCALL(ctx, inj_dbgptr, ctx->h_libdl);
	if(ctx->h_libdl == NULL){
		ctx->h_libdl = ctx->libdl.dlopen(ctx->libdl_name, RTLD_NOW | RTLD_GLOBAL);
	}

	if(ctx->h_libdl == NULL){
		return -1;
	}

	return PCALL(ctx, inj_fetchsym, ctx->h_libdl, (void **)&ctx->libdl.dlerror);
}

INLINE intptr_t inj_api_init(struct injcode_ctx *ctx){
	intptr_t result = 0;

	if(_inj_init_libdl(ctx) != 0){
		return -1;
	}
	result += PCALL(ctx, inj_fetchsym, ctx->h_libthread, (void **)&ctx->libthread.pthread_mutex_init);
	result += PCALL(ctx, inj_fetchsym, ctx->h_libthread, (void **)&ctx->libthread.pthread_mutex_lock);
	result += PCALL(ctx, inj_fetchsym, ctx->h_libthread, (void **)&ctx->libthread.pthread_mutex_unlock);
	result += PCALL(ctx, inj_fetchsym, ctx->h_libthread, (void **)&ctx->libthread.pthread_cond_init);
	result += PCALL(ctx, inj_fetchsym, ctx->h_libthread, (void **)&ctx->libthread.pthread_cond_wait);
	if(result != 0){
		return -1;
	}
	return 0;
}

INLINE intptr_t inj_load_prepare(struct injcode_ctx *ctx){
	UNUSED(ctx);
	return 0;
}
