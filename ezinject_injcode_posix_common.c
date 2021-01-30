struct dl_api {
	void *(*dlopen)(const char *filename, int flag);
	void *(*dlsym)(void *handle, const char *symbol);
	int (*dlclose)(void *handle);
	char *(*dlerror)(void);
};

struct thread_api {
	int (*pthread_mutex_init)(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
	int (*pthread_mutex_lock)(pthread_mutex_t *mutex);
	int (*pthread_mutex_unlock)(pthread_mutex_t *mutex);
	int (*pthread_cond_init)(pthread_cond_t *cond, const pthread_condattr_t *attr);
	int (*pthread_cond_wait)(pthread_cond_t *restrict cond, pthread_mutex_t *restrict mutex);
	int (*pthread_join)(pthread_t thread, void **retval);
};


INLINE void inj_puts(struct injcode_bearing *br, char *str){
	if(str == NULL){
		return;
	}

	int l;
	for(l=0; str[l] != 0x00; l++);
	br->libc_syscall(__NR_write, STDOUT_FILENO, str, l);
	char nl = '\n';
	
	br->libc_syscall(__NR_write, STDOUT_FILENO, &nl, 1);
}