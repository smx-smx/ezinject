AC_PREREQ([2.69])
AC_INIT([ezinject], [2.0], [smxdev4@gmail.com])
AC_CONFIG_SRCDIR([ezinject.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([foreign subdir-objects -Wall])

AC_CANONICAL_HOST

AC_PROG_CC
AC_PROG_CXX([optional])
AM_PROG_AR
LT_INIT([disable-static])

AC_PROG_INSTALL
AC_PROG_LN_S
AM_PROG_AS

AC_USE_SYSTEM_EXTENSIONS

AC_CHECK_SIZEOF([void *])

dnl ---------------------------------------------------------------------------
dnl Debug mode
dnl ---------------------------------------------------------------------------
AC_ARG_ENABLE([debug],
  [AS_HELP_STRING([--disable-debug], [disable debug build mode])],
  [enable_debug=$enableval],
  [enable_debug=yes])
AM_CONDITIONAL([DEBUG], [test "x$enable_debug" = xyes])

dnl Enable static conditional
AM_CONDITIONAL([ENABLE_STATIC], [test "x$enable_static" = xyes])

dnl C++ sample support
enable_cpp_samples=no
if test "x$ac_cv_prog_cxx_works" != xno && test -n "$CXX"; then
  enable_cpp_samples=yes
fi
AC_ARG_ENABLE([cpp-samples],
  [AS_HELP_STRING([--disable-cpp-samples], [disable C++ sample module])],
  [enable_cpp_samples=$enableval])
AM_CONDITIONAL([ENABLE_CPP_SAMPLES], [test "x$enable_cpp_samples" = xyes])

dnl C++ test support
AM_CONDITIONAL([HAVE_CXX], [test "x$ac_cv_prog_cxx_works" != xno && test -n "$CXX"])

dnl ---------------------------------------------------------------------------
dnl Static build
dnl ---------------------------------------------------------------------------
AC_ARG_ENABLE([static],
  [AS_HELP_STRING([--enable-static], [build ezinject as a static binary])],
  [enable_static=$enableval],
  [enable_static=no])

dnl ---------------------------------------------------------------------------
dnl OS detection
dnl ---------------------------------------------------------------------------
EZ_TARGET_LINUX=no
EZ_TARGET_FREEBSD=no
EZ_TARGET_DARWIN=no
EZ_TARGET_POSIX=no
EZ_TARGET_ANDROID=no
EZ_TARGET_WINDOWS=no

case "$host_os" in
  linux*android*)
    EZ_TARGET_LINUX=yes
    EZ_TARGET_POSIX=yes
    EZ_TARGET_ANDROID=yes
    ;;
  linux*)
    EZ_TARGET_LINUX=yes
    EZ_TARGET_POSIX=yes
    ;;
  gnu*|k*bsd*-gnu*)
    EZ_TARGET_LINUX=yes
    EZ_TARGET_POSIX=yes
    ;;
  freebsd*)
    EZ_TARGET_FREEBSD=yes
    EZ_TARGET_POSIX=yes
    ;;
  darwin*)
    EZ_TARGET_DARWIN=yes
    EZ_TARGET_POSIX=yes
    ;;
  mingw*|msys*|cygwin*)
    EZ_TARGET_WINDOWS=yes
    ;;
  *)
    AC_MSG_ERROR([Unsupported OS: $host_os])
    ;;
esac

AM_CONDITIONAL([EZ_TARGET_LINUX], [test "x$EZ_TARGET_LINUX" = xyes])
AM_CONDITIONAL([EZ_TARGET_FREEBSD], [test "x$EZ_TARGET_FREEBSD" = xyes])
AM_CONDITIONAL([EZ_TARGET_DARWIN], [test "x$EZ_TARGET_DARWIN" = xyes])
AM_CONDITIONAL([EZ_TARGET_POSIX], [test "x$EZ_TARGET_POSIX" = xyes])
AM_CONDITIONAL([EZ_TARGET_ANDROID], [test "x$EZ_TARGET_ANDROID" = xyes])
AM_CONDITIONAL([EZ_TARGET_WINDOWS], [test "x$EZ_TARGET_WINDOWS" = xyes])

dnl ---------------------------------------------------------------------------
dnl CPU architecture detection
dnl ---------------------------------------------------------------------------
EZ_ARCH_ARM=no
EZ_ARCH_ARM64=no
EZ_ARCH_I386=no
EZ_ARCH_AMD64=no
EZ_ARCH_MIPS=no
EZ_ARCH_PPC32=no
EZ_ARCH_PPC64=no
EZ_ARCH_RISCV=no
EZ_ARCH_HPPA=no

case "$host_cpu" in
  aarch64*)
    EZ_ARCH_ARM64=yes
    ;;
  arm*)
    EZ_ARCH_ARM=yes
    ;;
  i[[3456]]86)
    EZ_ARCH_I386=yes
    ;;
  x86_64|amd64)
    EZ_ARCH_AMD64=yes
    ;;
  mips*)
    EZ_ARCH_MIPS=yes
    ;;
  powerpc64*|ppc64*)
    EZ_ARCH_PPC64=yes
    ;;
  powerpc*|ppc*)
    EZ_ARCH_PPC32=yes
    ;;
  riscv*)
    EZ_ARCH_RISCV=yes
    ;;
  hppa*)
    EZ_ARCH_HPPA=yes
    ;;
  *)
    AC_MSG_WARN([Unknown CPU architecture: $host_cpu, will attempt compile-time detection])
    ;;
esac

AM_CONDITIONAL([EZ_ARCH_ARM], [test "x$EZ_ARCH_ARM" = xyes])
AM_CONDITIONAL([EZ_ARCH_ARM64], [test "x$EZ_ARCH_ARM64" = xyes])
AM_CONDITIONAL([EZ_ARCH_I386], [test "x$EZ_ARCH_I386" = xyes])
AM_CONDITIONAL([EZ_ARCH_AMD64], [test "x$EZ_ARCH_AMD64" = xyes])
AM_CONDITIONAL([EZ_ARCH_MIPS], [test "x$EZ_ARCH_MIPS" = xyes])
AM_CONDITIONAL([EZ_ARCH_PPC32], [test "x$EZ_ARCH_PPC32" = xyes])
AM_CONDITIONAL([EZ_ARCH_PPC64], [test "x$EZ_ARCH_PPC64" = xyes])
AM_CONDITIONAL([EZ_ARCH_RISCV], [test "x$EZ_ARCH_RISCV" = xyes])
AM_CONDITIONAL([EZ_ARCH_HPPA], [test "x$EZ_ARCH_HPPA" = xyes])

dnl ---------------------------------------------------------------------------
dnl ARM Thumb mode
dnl ---------------------------------------------------------------------------
AC_ARG_ENABLE([arm-thumb],
  [AS_HELP_STRING([--enable-arm-thumb], [use Thumb mode on ARM (default: ARM mode)])],
  [USE_ARM_THUMB=$enableval],
  [USE_ARM_THUMB=no])
AM_CONDITIONAL([USE_ARM_THUMB], [test "x$USE_ARM_THUMB" = xyes])

dnl ---------------------------------------------------------------------------
dnl Libc detection
dnl ---------------------------------------------------------------------------
EZ_LIBC=""
EZ_LIBC_VARIANT=""
AC_ARG_WITH([libc],
  [AS_HELP_STRING([--with-libc=TYPE], [force libc type: glibc, glibc-old, uclibc, bionic])],
  [EZ_LIBC=$withval])
AC_ARG_WITH([libc-variant],
  [AS_HELP_STRING([--with-libc-variant=VARIANT], [libc variant: old, android-2, android-5, android-10])],
  [EZ_LIBC_VARIANT=$withval])

dnl Dynamic linker name lookup
DYN_LINKER_NAME=""
DL_LIBRARY_NAME=""
C_LIBRARY_NAME=""
PTHREAD_LIBRARY_NAME=""

HAVE_LIBC_DLOPEN_MODE=no
HAVE_LIBC_DL_OPEN=no
HAVE_LIBDL_IN_LIBC=no
HAVE_DL_LOAD_SHARED_LIBRARY=no
UCLIBC_OLD=no
HAVE_LDR_LOAD_DLL=no
HAVE_LOADLIBRARY=no

if test "x$EZ_TARGET_WINDOWS" = xyes; then
  C_LIBRARY_NAME="ntdll.dll"
  DL_LIBRARY_NAME="kernel32.dll"
  PTHREAD_LIBRARY_NAME="kernel32.dll"
else
  dnl Find C library
  if test "x$EZ_TARGET_LINUX" = xyes; then
    for lib in libc.so.6 libc.so.0 libc.so; do
      AC_CHECK_LIB([c], [dlopen], [], [true], [-l$lib 2>/dev/null])
    done
    C_LIBRARY_NAME="libc.so.6"
  elif test "x$EZ_TARGET_FREEBSD" = xyes; then
    C_LIBRARY_NAME="libc.so.7"
  elif test "x$EZ_TARGET_DARWIN" = xyes; then
    C_LIBRARY_NAME="libSystem.B.dylib"
  fi

  dnl Find DL library
  if test "x$EZ_TARGET_LINUX" = xyes || test "x$EZ_TARGET_FREEBSD" = xyes; then
    DL_LIBRARY_NAME="libdl.so.2"
    AC_CHECK_LIB([dl], [dlopen], [HAVE_DLOPEN=yes])
    AC_CHECK_LIB([dl], [dlsym], [HAVE_DLSYM=yes])
  elif test "x$EZ_TARGET_DARWIN" = xyes; then
    DL_LIBRARY_NAME="libdl.dylib"
  fi

  dnl Check for glibc-specific __libc_dlopen_mode
  AC_CHECK_FUNCS([__libc_dlopen_mode], [HAVE_LIBC_DLOPEN_MODE=yes])

  dnl Check if libc has dlopen (glibc >= 2.34, FreeBSD)
  if test "x$HAVE_LIBC_DLOPEN_MODE" != xyes; then
    AC_CHECK_FUNCS([dlopen dlsym], [HAVE_LIBDL_IN_LIBC=yes])
  fi

  dnl uClibc detection
  if test "x$EZ_TARGET_LINUX" = xyes; then
    AC_CHECK_FILE([/lib/ld-uClibc.so.0],
      [DYN_LINKER_NAME="ld-uClibc.so.0"
       HAVE_DL_LOAD_SHARED_LIBRARY=yes])
    if test "x$EZ_ARCH_MIPS" = xyes && test "x$HAVE_DL_LOAD_SHARED_LIBRARY" = xyes; then
      UCLIBC_OLD=yes
    fi
  fi

  dnl Set dynamic linker name for FreeBSD
  if test "x$EZ_TARGET_FREEBSD" = xyes; then
    if test "x$EZ_ARCH_I386" = xyes; then
      DYN_LINKER_NAME="ld-elf32.so.1"
    else
      DYN_LINKER_NAME="ld-elf.so.1"
    fi
  fi

  if test "x$EZ_TARGET_DARWIN" = xyes; then
    DYN_LINKER_NAME="libdyld.dylib"
  fi

  dnl Find pthread library
  if test "x$EZ_TARGET_ANDROID" = xyes; then
    PTHREAD_LIBRARY_NAME="$C_LIBRARY_NAME"
  elif test "x$EZ_TARGET_DARWIN" = xyes; then
    dnl macOS 10.6 has pthread in libSystem.B; 10.7+ uses libsystem_pthread
    AC_CHECK_FILE([/usr/lib/libsystem_pthread.dylib],
      [PTHREAD_LIBRARY_NAME="libsystem_pthread.dylib"],
      [PTHREAD_LIBRARY_NAME="libSystem.B.dylib"])
  else
    AC_CHECK_LIB([pthread], [pthread_create],
      [PTHREAD_LIBRARY_NAME="libpthread.so.0"],
      [PTHREAD_LIBRARY_NAME="libpthread.so"])
  fi
fi

dnl Override libc detection if user specified type
if test "x$EZ_LIBC" = xglibc; then
  HAVE_LIBC_DLOPEN_MODE=yes
elif test "x$EZ_LIBC" = xglibc-old; then
  HAVE_LIBC_DL_OPEN=yes
elif test "x$EZ_LIBC" = xuclibc; then
  DYN_LINKER_NAME="ld-uClibc.so.0"
  HAVE_DL_LOAD_SHARED_LIBRARY=yes
  if test "x$EZ_LIBC_VARIANT" = xold; then
    UCLIBC_OLD=yes
  fi
fi

AC_SUBST([C_LIBRARY_NAME])
AC_SUBST([DL_LIBRARY_NAME])
AC_SUBST([DYN_LINKER_NAME])
AC_SUBST([PTHREAD_LIBRARY_NAME])

dnl Libc variant conditionals for Makefile.am
GENERIC_LIBC=no
if test "x$HAVE_LIBC_DLOPEN_MODE" != xyes && test "x$HAVE_LIBC_DL_OPEN" != xyes && test "x$HAVE_DL_LOAD_SHARED_LIBRARY" != xyes; then
  GENERIC_LIBC=yes
fi
AM_CONDITIONAL([HAVE_LIBC_DLOPEN_MODE_COND], [test "x$HAVE_LIBC_DLOPEN_MODE" = xyes])
AM_CONDITIONAL([HAVE_LIBC_DL_OPEN_COND], [test "x$HAVE_LIBC_DL_OPEN" = xyes])
AM_CONDITIONAL([HAVE_DL_LOAD_SHARED_LIBRARY_COND], [test "x$HAVE_DL_LOAD_SHARED_LIBRARY" = xyes])
AM_CONDITIONAL([GENERIC_LIBC_COND], [test "x$GENERIC_LIBC" = xyes])

dnl ---------------------------------------------------------------------------
dnl Feature tests
dnl ---------------------------------------------------------------------------

dnl PSR_T_BIT (ARM)
AC_CHECK_DECL([PSR_T_BIT], [HAVE_PSR_T_BIT=yes], [HAVE_PSR_T_BIT=no],
  [#include <asm/ptrace.h>])

dnl strsignal
AC_CHECK_FUNCS([strsignal], [HAVE_STRSIGNAL=yes], [HAVE_STRSIGNAL=no])

dnl RTLD_NOLOAD
AC_MSG_CHECKING([for RTLD_NOLOAD])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#define _GNU_SOURCE
#include <dlfcn.h>
]], [[int x = RTLD_NOLOAD; (void)x;]])],
  [HAVE_RTLD_NOLOAD=yes
   AC_MSG_RESULT([yes])],
  [HAVE_RTLD_NOLOAD=no
   AC_MSG_RESULT([no])])

dnl PTRACE_SETREGS
AC_CHECK_DECL([PTRACE_SETREGS], [HAVE_PTRACE_SETREGS=yes], [HAVE_PTRACE_SETREGS=no],
  [#include <sys/ptrace.h>])

dnl shm_open with exec flag
AC_MSG_CHECKING([for SHM_EXEC support])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#define _GNU_SOURCE
#include <sys/mman.h>
#include <fcntl.h>
]], [[int fd = shm_open("test", O_RDWR | O_EXEC, 0); (void)fd;]])],
  [HAVE_SHM_EXEC=yes
   AC_MSG_RESULT([yes])],
  [HAVE_SHM_EXEC=no
   AC_MSG_RESULT([no])])

dnl Android ashmen
AC_CHECK_HEADER([linux/ashmem.h], [USE_ANDROID_ASHMEM=yes], [USE_ANDROID_ASHMEM=no])

dnl memfd_create syscall number (for memloader sample)
AC_CHECK_DECL([__NR_memfd_create], [HAVE_NR_MEMFD_CREATE=yes], [HAVE_NR_MEMFD_CREATE=no],
  [#include <asm/unistd.h>])
AM_CONDITIONAL([HAVE_NR_MEMFD_CREATE], [test "x$HAVE_NR_MEMFD_CREATE" = xyes])

dnl HAVE_CPU_VLE (variable-length instruction encoding)
HAVE_CPU_VLE=no
if test "x$EZ_ARCH_I386" = xyes || test "x$EZ_ARCH_AMD64" = xyes; then
  HAVE_CPU_VLE=yes
fi
if test "x$EZ_ARCH_ARM" = xyes && test "x$USE_ARM_THUMB" = xyes; then
  HAVE_CPU_VLE=yes
fi

dnl ---------------------------------------------------------------------------
dnl Capstone (optional)
dnl ---------------------------------------------------------------------------
USE_CAPSTONE=no
AC_ARG_WITH([capstone],
  [AS_HELP_STRING([--with-capstone@<:@=PREFIX@:>@], [enable Capstone disassembler support])],
  [
    if test "x$withval" != xno; then
      if test "x$withval" != xyes; then
        CAPSTONE_PREFIX="$withval"
        CAPSTONE_CFLAGS="-I$withval/include"
        CAPSTONE_LIBS="-L$withval/lib -lcapstone"
      else
        CAPSTONE_CFLAGS=""
        CAPSTONE_LIBS="-lcapstone"
      fi
      SAVED_CFLAGS="$CFLAGS"
      SAVED_LIBS="$LIBS"
      CFLAGS="$CFLAGS $CAPSTONE_CFLAGS"
      LIBS="$LIBS $CAPSTONE_LIBS"
      AC_CHECK_HEADER([capstone/capstone.h],
        [AC_CHECK_LIB([capstone], [cs_open],
          [USE_CAPSTONE=yes],
          [AC_MSG_WARN([capstone library found but missing cs_open]); USE_CAPSTONE=no])],
        [AC_MSG_WARN([capstone/capstone.h not found]); USE_CAPSTONE=no])
      CFLAGS="$SAVED_CFLAGS"
      LIBS="$SAVED_LIBS"
    fi
  ])

if test "x$HAVE_CPU_VLE" = xyes && test "x$USE_CAPSTONE" = xno; then
  AC_MSG_NOTICE([Capstone required for variable-length instruction support, will search])
  SAVED_CFLAGS="$CFLAGS"
  SAVED_LIBS="$LIBS"
  CFLAGS="$CFLAGS $CAPSTONE_CFLAGS"
  LIBS="$LIBS $CAPSTONE_LIBS"
  AC_CHECK_HEADER([capstone/capstone.h],
    [AC_CHECK_LIB([capstone], [cs_open],
      [USE_CAPSTONE=yes
       CAPSTONE_CFLAGS=""
       CAPSTONE_LIBS="-lcapstone"],
      [AC_MSG_WARN([capstone not found, VLE disabled]); USE_CAPSTONE=no])],
    [AC_MSG_WARN([capstone not found, VLE disabled]); USE_CAPSTONE=no])
  CFLAGS="$SAVED_CFLAGS"
  LIBS="$SAVED_LIBS"
fi

AM_CONDITIONAL([USE_CAPSTONE], [test "x$USE_CAPSTONE" = xyes])
AC_SUBST([CAPSTONE_CFLAGS])
AC_SUBST([CAPSTONE_LIBS])

dnl ---------------------------------------------------------------------------
dnl frida-gum (optional)
dnl ---------------------------------------------------------------------------
USE_FRIDA_GUM=no
AC_ARG_WITH([frida-gum],
  [AS_HELP_STRING([--with-frida-gum], [enable frida-gum integration])],
  [USE_FRIDA_GUM=$withval])
AM_CONDITIONAL([USE_FRIDA_GUM], [test "x$USE_FRIDA_GUM" = xyes])

dnl ---------------------------------------------------------------------------
dnl Architecture header selection
dnl ---------------------------------------------------------------------------
EZ_ARCH_HEADER=""
if test "x$EZ_TARGET_LINUX" = xyes; then
  if test "x$EZ_ARCH_ARM64" = xyes; then
    EZ_ARCH_HEADER="arch/ezinject_aarch64.h"
  elif test "x$EZ_ARCH_ARM" = xyes; then
    EZ_ARCH_HEADER="arch/ezinject_arm.h"
  elif test "x$EZ_ARCH_I386" = xyes; then
    EZ_ARCH_HEADER="arch/ezinject_i386.h"
  elif test "x$EZ_ARCH_AMD64" = xyes; then
    EZ_ARCH_HEADER="arch/ezinject_amd64.h"
  elif test "x$EZ_ARCH_MIPS" = xyes; then
    EZ_ARCH_HEADER="arch/ezinject_mips.h"
  elif test "x$EZ_ARCH_PPC32" = xyes; then
    EZ_ARCH_HEADER="arch/ezinject_ppc32.h"
  elif test "x$EZ_ARCH_PPC64" = xyes; then
    EZ_ARCH_HEADER="arch/ezinject_ppc64.h"
  elif test "x$EZ_ARCH_RISCV" = xyes; then
    EZ_ARCH_HEADER="arch/ezinject_riscv.h"
  elif test "x$EZ_ARCH_HPPA" = xyes; then
    EZ_ARCH_HEADER="arch/ezinject_hppa.h"
  fi
elif test "x$EZ_TARGET_FREEBSD" = xyes; then
  if test "x$EZ_ARCH_AMD64" = xyes; then
    EZ_ARCH_HEADER="arch/ezinject_freebsd_amd64.h"
  elif test "x$EZ_ARCH_I386" = xyes; then
    EZ_ARCH_HEADER="arch/ezinject_freebsd_i386.h"
  fi
elif test "x$EZ_TARGET_DARWIN" = xyes; then
  if test "x$EZ_ARCH_AMD64" = xyes; then
    EZ_ARCH_HEADER="arch/ezinject_darwin_amd64.h"
  fi
elif test "x$EZ_TARGET_WINDOWS" = xyes; then
  if test "x$EZ_ARCH_AMD64" = xyes; then
    EZ_ARCH_HEADER="arch/ezinject_windows_amd64.h"
  elif test "x$EZ_ARCH_I386" = xyes; then
    EZ_ARCH_HEADER="arch/ezinject_windows_i386.h"
  fi
fi

if test -z "$EZ_ARCH_HEADER"; then
  AC_MSG_ERROR([Unsupported architecture/OS combination: $host_cpu-$host_os])
fi
AC_SUBST([EZ_ARCH_HEADER])

dnl ---------------------------------------------------------------------------
dnl Compiler flag checks
dnl ---------------------------------------------------------------------------
AX_CHECK_COMPILE_FLAG([-Wextra], [CFLAGS="$CFLAGS -Wextra"])
AX_CHECK_COMPILE_FLAG([-Werror=implicit-function-declaration], [CFLAGS="$CFLAGS -Werror=implicit-function-declaration"])
AX_CHECK_COMPILE_FLAG([-Wno-unused-parameter], [CFLAGS="$CFLAGS -Wno-unused-parameter"])
AX_CHECK_COMPILE_FLAG([-Wno-cast-function-type], [CFLAGS="$CFLAGS -Wno-cast-function-type"])
AX_CHECK_COMPILE_FLAG([-ffunction-sections], [CFLAGS="$CFLAGS -ffunction-sections"])
AX_CHECK_COMPILE_FLAG([-fdata-sections], [CFLAGS="$CFLAGS -fdata-sections"])
AX_CHECK_COMPILE_FLAG([-fPIC], [PIC_FLAG="-fPIC"], [PIC_FLAG=""])

AX_CHECK_COMPILE_FLAG([-fno-jump-tables], [INJCODE_NO_JUMP_TABLES="-fno-jump-tables"])
AX_CHECK_COMPILE_FLAG([-fno-stack-protector], [INJCODE_NO_STACK_PROT="-fno-stack-protector"])
AX_CHECK_COMPILE_FLAG([-mno-stack-arg-probe], [INJCODE_NO_STACK_ARG="-mno-stack-arg-probe"])

dnl Select injection code optimization level
if test "x$EZ_ARCH_PPC32" = xyes || test "x$EZ_ARCH_PPC64" = xyes || test "x$EZ_ARCH_HPPA" = xyes; then
  INJCODE_OPT="-O2"
else
  INJCODE_OPT="-Os"
fi

dnl Build base injection code flags
INJCODE_CFLAGS="$INJCODE_OPT -fno-stack-check -fno-pic -nostdlib -fomit-frame-pointer -ffreestanding"
if test -n "$INJCODE_NO_JUMP_TABLES"; then
  INJCODE_CFLAGS="$INJCODE_CFLAGS $INJCODE_NO_JUMP_TABLES"
fi
if test -n "$INJCODE_NO_STACK_PROT"; then
  INJCODE_CFLAGS="$INJCODE_CFLAGS $INJCODE_NO_STACK_PROT"
fi
if test -n "$INJCODE_NO_STACK_ARG"; then
  INJCODE_CFLAGS="$INJCODE_CFLAGS $INJCODE_NO_STACK_ARG"
fi
if test "x$EZ_ARCH_HPPA" = xyes; then
  INJCODE_CFLAGS="$INJCODE_CFLAGS -mfast-indirect-calls"
fi

AC_SUBST([INJCODE_CFLAGS])

dnl GNU99 check (for gcc 3.x)
AX_CHECK_COMPILE_FLAG([-std=gnu99], [CFLAGS="$CFLAGS -std=gnu99"])

dnl ---------------------------------------------------------------------------
dnl config.h defines
dnl ---------------------------------------------------------------------------
if test "x$enable_debug" = xyes; then
  AC_DEFINE([DEBUG], [1], [Define to 1 for debug build])
fi

if test "x$EZ_ARCH_ARM" = xyes; then
  AC_DEFINE([EZ_ARCH_ARM], [1], [Define to 1 for ARM])
fi
if test "x$EZ_ARCH_ARM64" = xyes; then
  AC_DEFINE([EZ_ARCH_ARM64], [1], [Define to 1 for ARM64/AArch64])
fi
if test "x$EZ_ARCH_I386" = xyes; then
  AC_DEFINE([EZ_ARCH_I386], [1], [Define to 1 for i386])
fi
if test "x$EZ_ARCH_AMD64" = xyes; then
  AC_DEFINE([EZ_ARCH_AMD64], [1], [Define to 1 for AMD64/x86_64])
fi
if test "x$EZ_ARCH_MIPS" = xyes; then
  AC_DEFINE([EZ_ARCH_MIPS], [1], [Define to 1 for MIPS])
fi
if test "x$EZ_ARCH_PPC32" = xyes; then
  AC_DEFINE([EZ_ARCH_PPC32], [1], [Define to 1 for PowerPC 32-bit])
fi
if test "x$EZ_ARCH_PPC64" = xyes; then
  AC_DEFINE([EZ_ARCH_PPC64], [1], [Define to 1 for PowerPC 64-bit])
fi
if test "x$EZ_ARCH_HPPA" = xyes; then
  AC_DEFINE([EZ_ARCH_HPPA], [1], [Define to 1 for HPPA])
fi

if test "x$EZ_TARGET_LINUX" = xyes; then
  AC_DEFINE([EZ_TARGET_LINUX], [1], [Define to 1 for Linux])
fi
if test "x$EZ_TARGET_FREEBSD" = xyes; then
  AC_DEFINE([EZ_TARGET_FREEBSD], [1], [Define to 1 for FreeBSD])
fi
if test "x$EZ_TARGET_POSIX" = xyes; then
  AC_DEFINE([EZ_TARGET_POSIX], [1], [Define to 1 for POSIX])
fi
if test "x$EZ_TARGET_ANDROID" = xyes; then
  AC_DEFINE([EZ_TARGET_ANDROID], [1], [Define to 1 for Android])
fi
if test "x$EZ_TARGET_WINDOWS" = xyes; then
  AC_DEFINE([EZ_TARGET_WINDOWS], [1], [Define to 1 for Windows])
fi
if test "x$EZ_TARGET_DARWIN" = xyes; then
  AC_DEFINE([EZ_TARGET_DARWIN], [1], [Define to 1 for Darwin/macOS])
fi

if test "x$HAVE_CPU_VLE" = xyes; then
  AC_DEFINE([HAVE_CPU_VLE], [1], [Define to 1 if CPU uses variable-length instructions])
fi
if test "x$HAVE_SHM_EXEC" = xyes; then
  AC_DEFINE([HAVE_SHM_EXEC], [1], [Define to 1 if shm_open supports O_EXEC])
fi
if test "x$HAVE_STRSIGNAL" = xyes; then
  AC_DEFINE([HAVE_STRSIGNAL], [1], [Define to 1 if strsignal is available])
fi
if test "x$HAVE_LIBC_DLOPEN_MODE" = xyes; then
  AC_DEFINE([HAVE_LIBC_DLOPEN_MODE], [1], [Define to 1 for glibc __libc_dlopen_mode])
fi
if test "x$HAVE_LIBC_DL_OPEN" = xyes; then
  AC_DEFINE([HAVE_LIBC_DL_OPEN], [1], [Define to 1 for glibc old dl_open])
fi
if test "x$HAVE_DL_LOAD_SHARED_LIBRARY" = xyes; then
  AC_DEFINE([HAVE_DL_LOAD_SHARED_LIBRARY], [1], [Define to 1 for uClibc _dl_load_shared_library])
fi
if test "x$HAVE_LIBDL_IN_LIBC" = xyes; then
  AC_DEFINE([HAVE_LIBDL_IN_LIBC], [1], [Define to 1 if dlopen is in libc])
fi
if test "x$HAVE_RTLD_NOLOAD" = xyes; then
  AC_DEFINE([HAVE_RTLD_NOLOAD], [1], [Define to 1 if RTLD_NOLOAD is available])
fi
if test "x$HAVE_PTRACE_SETREGS" = xyes; then
  AC_DEFINE([HAVE_PTRACE_SETREGS], [1], [Define to 1 if PTRACE_SETREGS is available])
fi
if test "x$HAVE_PSR_T_BIT" = xyes; then
  AC_DEFINE([HAVE_PSR_T_BIT], [1], [Define to 1 if PSR_T_BIT is available])
fi
if test "x$USE_ANDROID_ASHMEM" = xyes; then
  AC_DEFINE([USE_ANDROID_ASHMEM], [1], [Define to 1 for Android ashmem])
fi
if test "x$USE_ARM_THUMB" = xyes; then
  AC_DEFINE([USE_ARM_THUMB], [1], [Define to 1 for ARM Thumb mode])
fi
if test "x$USE_CAPSTONE" = xyes; then
  AC_DEFINE([USE_CAPSTONE], [1], [Define to 1 to enable Capstone])
fi
if test "x$USE_FRIDA_GUM" = xyes; then
  AC_DEFINE([USE_FRIDA_GUM], [1], [Define to 1 to enable frida-gum])
fi
if test "x$UCLIBC_OLD" = xyes; then
  AC_DEFINE([UCLIBC_OLD], [1], [Define to 1 for old uClibc])
fi

AC_DEFINE_UNQUOTED([EZ_ARCH_HEADER], ["$EZ_ARCH_HEADER"], [Architecture-specific header path])
AC_DEFINE_UNQUOTED([C_LIBRARY_NAME], ["$C_LIBRARY_NAME"], [C library name])
AC_DEFINE_UNQUOTED([DYN_LINKER_NAME], ["$DYN_LINKER_NAME"], [Dynamic linker name])
AC_DEFINE_UNQUOTED([DL_LIBRARY_NAME], ["$DL_LIBRARY_NAME"], [DL library name])
AC_DEFINE_UNQUOTED([PTHREAD_LIBRARY_NAME], ["$PTHREAD_LIBRARY_NAME"], [Pthread library name])

AH_VERBATIM([HAVE_SYSCALLS_AND_SHELLCODE],
[/* NOTE: Windows uses emulated syscalls to map mmap to VirtualAlloc and munmap to VirtualFree */
#if (defined(EZ_TARGET_POSIX) || defined(EZ_TARGET_WINDOWS)) && !defined(EZ_TARGET_DARWIN)
#define HAVE_SYSCALLS 1
#endif

#ifdef HAVE_SYSCALLS
#define HAVE_SHELLCODE 1
#endif

/* Map autotools SIZEOF_VOID_P to the name used by netapi sample */
#if defined(SIZEOF_VOID_P) && !defined(CMAKE_SIZEOF_VOID_P)
#define CMAKE_SIZEOF_VOID_P SIZEOF_VOID_P
#endif])

dnl ---------------------------------------------------------------------------
dnl Substitutions for Makefile.am
dnl ---------------------------------------------------------------------------
AC_SUBST([EZINJECT_CFLAGS], ["-D__STDC_FORMAT_MACROS -I\$(top_srcdir) -I\$(top_builddir) -I\$(top_srcdir)/crt/lh"])

dnl Linker flags
if test "x$EZ_TARGET_DARWIN" = xyes; then
  UNDEFINED_FLAG="-Wl,-undefined,error"
elif test "x$EZ_TARGET_WINDOWS" = xyes; then
  UNDEFINED_FLAG="-no-undefined"
else
  UNDEFINED_FLAG="-Wl,--no-undefined"
fi
AC_SUBST([UNDEFINED_FLAG])

dnl Static link option
STATIC_FLAG=""
if test "x$enable_static" = xyes; then
  STATIC_FLAG="-static"
fi
AC_SUBST([STATIC_FLAG])

dnl ARM mode flags
ARM_ARCH_FLAG=""
if test "x$EZ_ARCH_ARM" = xyes; then
  if test "x$USE_ARM_THUMB" = xyes; then
    ARM_ARCH_FLAG="-mthumb"
  else
    ARM_ARCH_FLAG="-marm"
  fi
fi
AC_SUBST([ARM_ARCH_FLAG])

dnl POSIX PIC flag
POSIX_PIC_FLAG=""
if test "x$EZ_TARGET_POSIX" = xyes; then
  POSIX_PIC_FLAG="$PIC_FLAG"
fi
AC_SUBST([POSIX_PIC_FLAG])

dnl libdl link flag
LIBDL_LINK=""
if test "x$EZ_TARGET_POSIX" = xyes && test "x$HAVE_LIBDL_IN_LIBC" != xyes && test "x$EZ_TARGET_DARWIN" != xyes; then
  LIBDL_LINK="-ldl"
fi
AC_SUBST([LIBDL_LINK])

dnl pthread link flag
LIBPTHREAD_LINK=""
if test "x$EZ_TARGET_LINUX" = xyes || test "x$EZ_TARGET_FREEBSD" = xyes; then
  LIBPTHREAD_LINK="-lpthread"
fi
AC_SUBST([LIBPTHREAD_LINK])

dnl LH CPU architecture sources
LH_CPU_DIR=""
if test "x$EZ_ARCH_ARM" = xyes; then
  LH_CPU_DIR="arm"
elif test "x$EZ_ARCH_ARM64" = xyes; then
  LH_CPU_DIR="arm64"
elif test "x$EZ_ARCH_MIPS" = xyes; then
  LH_CPU_DIR="mips"
elif test "x$USE_CAPSTONE" = xyes; then
  if test "x$EZ_ARCH_I386" = xyes || test "x$EZ_ARCH_AMD64" = xyes; then
    LH_CPU_DIR="intel"
  fi
fi
AC_SUBST([LH_CPU_DIR])

AM_CONDITIONAL([LH_CPU_ARM], [test "x$LH_CPU_DIR" = xarm])
AM_CONDITIONAL([LH_CPU_ARM64], [test "x$LH_CPU_DIR" = xarm64])
AM_CONDITIONAL([LH_CPU_MIPS], [test "x$LH_CPU_DIR" = xmips])
AM_CONDITIONAL([LH_CPU_INTEL], [test "x$LH_CPU_DIR" = xintel])
AM_CONDITIONAL([LH_ENABLED], [test -n "$LH_CPU_DIR"])

AC_SUBST([CAPSTONE_CFLAGS])
AC_SUBST([CAPSTONE_LIBS])

dnl ---------------------------------------------------------------------------
dnl Output
dnl ---------------------------------------------------------------------------
AC_CONFIG_FILES([Makefile ezinject.pc])
AC_OUTPUT
