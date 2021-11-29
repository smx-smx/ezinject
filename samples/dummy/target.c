#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

#ifdef EZ_TARGET_POSIX
#include <signal.h>
#endif

#ifdef EZ_TARGET_LINUX
#include <asm/unistd.h>
#endif

#define UNUSED(x) (void)x

#ifdef EZ_TARGET_WINDOWS
#define EXPORT __declspec(dllexport)
#else
#define EXPORT extern
#endif

#ifdef EZ_TARGET_LINUX
#include <elf.h>
#include <link.h>
#endif

EXPORT int func1(int arg1, int arg2) {
	printf("arg1: %d, arg2: %d\n", arg1, arg2);
	return arg1 + arg2;
}

EXPORT void func2(void) {
	puts("Func2 called!");
}

#ifdef EZ_TARGET_POSIX
void onSignal(int sigNum){
	UNUSED(sigNum);
	printf("Error: got signal %d (%s)\n", sigNum, strsignal(sigNum));
	raise(SIGSTOP);
}
#endif

#ifdef EZ_TARGET_LINUX
void print_maps(){
	pid_t pid = getpid();
	char *path;
	asprintf(&path, "/proc/%u/maps", pid);
	do {
		FILE *fh = fopen(path, "r");
		if(!fh){
			return;
		}
		
		char line[256];
		while(!feof(fh)){
			fgets(line, sizeof(line), fh);
			fputs(line, stdout);
		}
		fclose(fh);
	} while(0);
	free(path);
}

void inspect_stack(uint8_t *stack_top, size_t stack_size){
  // assume we're external, read our cmdline
  FILE *cmdline = fopen("/proc/self/cmdline", "rb");
  int ch = -1; int len = 0;
  for(len=0; ch != 0; len++){
    ch = fgetc(cmdline);
  }
  int argv0_sz = len + 1;
  char *argv0 = malloc(argv0_sz);
  rewind(cmdline);
  fread(argv0, 1, argv0_sz, cmdline);
  fclose(cmdline);

  puts(argv0);

  int occurrences = 0;

  // find where argv0 is in the stack
  ssize_t remaining = (ssize_t)(stack_size - argv0_sz);
  uint8_t *p = stack_top - argv0_sz;
  for(; remaining > 0; remaining--, p--){
    if(!strncmp(p, argv0, argv0_sz)){
      if(occurrences++ > 0){
        // skip "_" environment var
        if(*(p - 1) != '=') break;
      }
    }
  }
  int found = 0;

  found = remaining != 0;
  if(!found) return;

  void *argv0_addr = p;
  printf("argv0: %p\n", argv0_addr);

  uintptr_t msk = ~(sizeof(uintptr_t)-1);
  void **pwords = (void **)((uintptr_t)p & msk);
  for(; remaining > 0; remaining-=sizeof(void *), pwords--){
	//if(*pwords != 0)
	//	printf("%p %p\n", pwords, *pwords);
    if(*pwords == argv0_addr){
      break;
    }
  }
  p = (uint8_t *)pwords;
  
  found = remaining != 0;
  if(!found) return;

  void *argv0_ptr = p;

  printf("argv0_ptr: %p\n", argv0_ptr);

  // good, now find auxv
  // step 1: skip all argv
  char **strp = (char **)argv0_ptr;
  while(*(strp++) != NULL);

  // step 2: skip all envp
  while(*(strp++) != NULL);

  printf("recovered auxv: %p\n", strp);

}

int get_stack(void **stack_begin, void **stack_end){
  pid_t pid = getpid();
  char cmd[128];
  sprintf(cmd, "grep stack /proc/%u/maps", pid);
  FILE *hCmd = popen(cmd, "r");
  fscanf(hCmd, "%p-%p", stack_begin, stack_end);
  pclose(hCmd);
  return 0;
}
#endif

int main(int argc, char *argv[], char *envp[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	UNUSED(argv);

	#ifdef EZ_TARGET_POSIX
	/*
	signal(SIGSEGV, onSignal);
	signal(SIGTRAP, onSignal);
	signal(SIGABRT, onSignal);
	*/
	#endif

	#ifdef EZ_TARGET_LINUX
	print_maps();
	{
		int i = 0 ;
		char **p = envp;
		while(*(p++) != NULL);
		printf("argv: %p %p\n", argv, argv[0]);
		printf("auxv: %p\n", p);
		ElfW(auxv_t) *auxv = (ElfW(auxv_t) *)p;
		for (; auxv->a_type != AT_NULL; auxv++)
			/* auxv->a_type = AT_NULL marks the end of auxv */
		{
			printf("%lu %u %u \n", (auxv->a_type), AT_PLATFORM, i++);
			if( auxv->a_type == AT_PLATFORM){
				printf("AT_PLATFORM is: %s\n", ((char*)auxv->a_un.a_val));
			}
		}
		puts("===============");
		void *stack_begin = NULL;
		void *stack_end = NULL;
		get_stack(&stack_begin, &stack_end);
		inspect_stack(stack_end, (uintptr_t)stack_end - (uintptr_t)stack_begin);
	}	
	#endif

	int interactive = argc > 1;
	printf("pid=%d\n&main=%p\n&return2=%p\n&func2=%p\n", getpid(), main, func1, func2);
	for(;;)
	{
		int val = func1(0, 1);
		printf("return1() = %d\n", val);
		if(!val)
			break;
		if(interactive)
			fgetc(stdin);
		else
			usleep(1000 * 1000);
	}
	return 0;
}
