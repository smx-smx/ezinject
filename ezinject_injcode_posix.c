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


	api->pthread_mutex_lock(&br->mutex);
	while(!br->loaded_signal){
		api->pthread_cond_wait(&br->cond, &br->mutex);
	}
	api->pthread_mutex_unlock(&br->mutex);

	// wait for user thread to die
	inj_dchar(br, 'j');

	void *result = NULL;
	api->pthread_join(br->user_tid, &result);
	
	*pExitStatus = (intptr_t)result;
	return 0;
}

INLINE intptr_t _inj_init_libdl(struct injcode_ctx *ctx){
	struct injcode_bearing *br = ctx->br;

	inj_puts(br, ctx->libdl_name);

	// just to make sure it's really loaded
	ctx->h_libdl = ctx->libdl.dlopen(ctx->libdl_name, RTLD_NOLOAD);
	inj_dbgptr(br, ctx->h_libdl);
	if(ctx->h_libdl == NULL){
		ctx->h_libdl = ctx->libdl.dlopen(ctx->libdl_name, RTLD_NOW | RTLD_GLOBAL);
	}

	if(ctx->h_libdl == NULL){
		return -1;
	}

	return fetch_sym(ctx, ctx->h_libdl, (void **)&ctx->libdl.dlerror);
}

INLINE intptr_t inj_api_init(struct injcode_ctx *ctx){
	intptr_t result = 0;

	if(_inj_init_libdl(ctx) != 0){
		return -1;
	}
	result += fetch_sym(ctx, ctx->h_libthread, (void **)&ctx->libthread.pthread_mutex_init);
	result += fetch_sym(ctx, ctx->h_libthread, (void **)&ctx->libthread.pthread_mutex_lock);
	result += fetch_sym(ctx, ctx->h_libthread, (void **)&ctx->libthread.pthread_mutex_unlock);
	result += fetch_sym(ctx, ctx->h_libthread, (void **)&ctx->libthread.pthread_cond_init);
	result += fetch_sym(ctx, ctx->h_libthread, (void **)&ctx->libthread.pthread_cond_wait);
	result += fetch_sym(ctx, ctx->h_libthread, (void **)&ctx->libthread.pthread_join);
	if(result != 0){
		return -1;
	}
	return 0;
}

INLINE intptr_t inj_load_prepare(struct injcode_ctx *ctx){
	UNUSED(ctx);
	return 0;
}