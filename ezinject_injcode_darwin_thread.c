/*
 * Darwin thread management for injected payload.
 * The injector creates the payload thread via thread_create_running (no TLS).
 * This code spawns a proper pthread (with TLS) and handles parent/child roles.
 */
static INLINE intptr_t inj_darwin_thread_setup(
	struct injcode_ctx *ctx, struct injcode_bearing *br)
{
	if(!br->platform.pthread_create_from_mach_thread)
		return 0;

	if(br->platform.tid == 0){
		PCALL(ctx, inj_dchar, 't');

		br->platform.mach_thread = br->platform.mach_thread_self();

		if(br->platform.pthread_create_from_mach_thread(
			&br->platform.tid, NULL,
			(typeof(void *(*)(void *)))br->entry.wrapper.target.fptr, ctx
		) != 0){
			PCALL(ctx, inj_dchar, '!');
			return INJ_ERR_DARWIN_THREAD;
		}
		return 1;
	} else {
		if(br->platform.pthread_detach(br->platform.pthread_self()) != 0)
			PCALL(ctx, inj_dchar, '!');

		if(br->platform.thread_terminate(br->platform.mach_thread) != KERN_SUCCESS)
			PCALL(ctx, inj_dchar, '!');

		return 0;
	}
}
