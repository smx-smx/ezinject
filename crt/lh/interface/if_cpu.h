#ifndef __INTERFACE_CPU_H
#define __INTERFACE_CPU_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#if defined(__linux__) || defined(__FreeBSD__)
#include <sys/wait.h>
#endif
#include <errno.h>

#include "config.h"

#if __android__
struct user {
	long uregs[18];
};
#elif defined(__linux__)
#include <sys/user.h>
#endif

#ifdef __FreeBSD__
#include <x86/reg.h>
#define r15 r_r15
#define r14 r_r14
#define r13 r_r13
#define r12 r_r12
#define rbp r_rbp
#define rbx r_rbx
#define r11 r_r11
#define r10 r_r10
#define r9 r_r9
#define r8 r_r8
#define rax r_rax
#define rcx r_rcx
#define rdx r_rdx
#define rsi r_rsi
#define rdi r_rdi
#define rip r_rip
#define cs r_cs
#define eflags r_eflags
#define rsp r_rsp
#define ss r_ss
#define fs_base r_fs_base
#define gs_base r_gs_base
#define ds r_ds
#define es r_es
#define fs r_fs
#define gs r_gs
struct user
{
  struct reg       regs;
  int                           u_fpvalid;
  unsigned long int             u_tsize;
  unsigned long int             u_dsize;
  unsigned long int             u_ssize;
  unsigned long                 start_code;
  unsigned long                 start_stack;
  long int                      signal;
  int                           reserved;
  unsigned long int             magic;
  char                          u_comm [32];
  unsigned long int             u_debugreg [8];
};
#endif

#ifdef HAVE_CPU_VLE
#include <capstone/capstone.h>
#endif

/*
 * Common Functions
 */
size_t inj_getjmp_size();
uint8_t *inj_build_jump(void *dstAddr, void *srcAddr, size_t *jumpSz);
void *inj_code_addr(void *func_addr);

int inj_getbackup_size(void *codePtr, unsigned int payloadSz);
int inj_relocate_code(void *codePtr, unsigned int codeSz, void *sourcePC, void *destPC);


/*
 * Per-CPU Functions
 */
int inj_opcode_bytes();
int inj_absjmp_opcode_bytes();
int inj_reljmp_opcode_bytes();

#ifndef __arm__
int inj_getinsn_count(void *buf, size_t sz, unsigned int *validbytes);
#endif

int inj_build_rel_jump(uint8_t *buffer, void *jump_destination, void *jump_opcode_address);
int inj_build_abs_jump(uint8_t *buffer, void *jump_destination, void *jump_opcode_address);
int inj_reljmp_opcode_bytes();
#endif
