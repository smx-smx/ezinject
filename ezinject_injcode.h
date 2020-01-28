#include <sys/types.h>
#include <linux/limits.h>

#define MAPPINGSIZE 8192
#define STACKSIZE 1024
#define INJ_PATH_MAX 128

struct injcode_user {
	// any user data here
};

struct injcode_bearing
{
	void *(*libc_dlopen_mode)(const char *name, int mode);
	long (*libc_syscall)(long number, ...);
	int (*libc_clone)(
		int (*fn)(void *),
		void *stack, int flags, void *arg, ...);
	struct injcode_user user;
	void *lib_handle;
	int argc;
	int dyn_size;
	char *argv[];
};

extern int clone_fn(void *arg);

extern void injected_sc_start();
extern void injected_sc_end();

extern void injected_clone_entry();
extern void clone_entry();

extern void injected_clone();

extern void injected_code_start();
extern void injected_code_end();
