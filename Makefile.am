ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = \
	-Wall \
	$(POSIX_PIC_FLAG) \
	$(ARM_ARCH_FLAG) \
	-D__STDC_FORMAT_MACROS

if EZ_TARGET_WINDOWS
AM_CFLAGS += -D_GNU_SOURCE
endif

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	-I$(top_srcdir)/crt/lh

bin_PROGRAMS = ezinject
lib_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_LTLIBRARIES =
CLEANFILES =
EXTRA_DIST =

ezinject_SOURCES =
ezinject_CFLAGS = $(AM_CFLAGS)
ezinject_LDADD =
ezinject_LDFLAGS =

# ---------------------------------------------------------------------------
# Utility and log convenience libraries
# ---------------------------------------------------------------------------
noinst_LTLIBRARIES += libezinject_util.la libezinject_log.la

libezinject_util_la_SOURCES = ezinject_util.c ezinject_util.h

libezinject_log_la_SOURCES = log.c log.h
libezinject_log_la_CFLAGS = $(AM_CFLAGS)

ezinject_LDADD += libezinject_util.la libezinject_log.la

# ---------------------------------------------------------------------------
# ELF parsing (Linux only)
# ---------------------------------------------------------------------------
if EZ_TARGET_LINUX
noinst_LTLIBRARIES += libelfparse.la
bin_PROGRAMS += ezpatch

libelfparse_la_SOURCES = elfparse.c elfparse.h

ezinject_LDADD += libelfparse.la

ezpatch_SOURCES = ezpatch.c elfparse.c elfparse.h ezinject_util.c log.c
ezpatch_CFLAGS = $(AM_CFLAGS)
ezpatch_LDADD = libezinject_util.la libezinject_log.la libos_linux_util.la $(LIBDL_LINK)
endif

# ---------------------------------------------------------------------------
# OS-specific convenience libraries
# ---------------------------------------------------------------------------

# Linux OS layer
if EZ_TARGET_LINUX
noinst_LTLIBRARIES += libos_linux_util.la libos_linux.la

libos_linux_util_la_SOURCES = os/linux/util.c

libos_linux_la_SOURCES = \
	os/linux/common.c \
	os/linux/inject.c \
	os/linux/remote.c \
	os/linux/builder.c \
	os/builder.h

if HAVE_LIBC_DLOPEN_MODE_COND
libos_linux_la_SOURCES += os/linux/libc_glibc.c
endif
if HAVE_LIBC_DL_OPEN_COND
libos_linux_la_SOURCES += os/linux/libc_glibc.c
endif
if HAVE_DL_LOAD_SHARED_LIBRARY_COND
libos_linux_la_SOURCES += os/linux/libc_uclibc.c
endif
if GENERIC_LIBC_COND
libos_linux_la_SOURCES += os/linux/libc_generic.c
endif

ezinject_LDADD += libos_linux.la libos_linux_util.la
endif

# POSIX shared layer
if EZ_TARGET_POSIX
noinst_LTLIBRARIES += libos_posix.la libos_posix_util.la

libos_posix_la_SOURCES = os/posix/remote.c
libos_posix_util_la_SOURCES = os/posix/util.c

ezinject_LDADD += libos_posix.la libos_posix_util.la
endif

# os_posix_shellcode provides trap symbols needed on ALL platforms
noinst_LTLIBRARIES += libos_posix_shellcode.la
libos_posix_shellcode_la_SOURCES = os/posix/inject.c
ezinject_LDADD += libos_posix_shellcode.la

# Darwin OS layer
if EZ_TARGET_DARWIN
noinst_LTLIBRARIES += libos_darwin.la

libos_darwin_la_SOURCES = \
	os/darwin/inject.c \
	os/darwin/libc_darwin.c \
	os/darwin/remote.c \
	os/darwin/util.c \
	os/darwin/builder.c

ezinject_LDADD += libos_darwin.la
endif

# FreeBSD OS layer
if EZ_TARGET_FREEBSD
noinst_LTLIBRARIES += libos_freebsd.la

libos_freebsd_la_SOURCES = \
	os/freebsd/inject.c \
	os/freebsd/libc_freebsd.c \
	os/freebsd/remote.c \
	os/freebsd/util.c \
	os/freebsd/builder.c

ezinject_LDADD += libos_freebsd.la
endif

# Android OS layer
if EZ_TARGET_ANDROID
noinst_LTLIBRARIES += libos_android.la

libos_android_la_SOURCES = os/android/libc_bionic.c

ezinject_LDADD += libos_android.la libelfparse.la
endif

# Windows OS layer
if EZ_TARGET_WINDOWS
noinst_LTLIBRARIES += libos_windows.la libos_windows_util.la libwindows_injlib.la

libos_windows_la_SOURCES = \
	os/windows/inject.c \
	os/windows/libc_windows.c \
	os/windows/remote.c \
	os/windows/builder.c

libos_windows_util_la_SOURCES = os/windows/util.c os/windows/util.h

libwindows_injlib_la_SOURCES = \
	os/windows/InjLib/GetProcAddress.c \
	os/windows/InjLib/GetProcAddress.h \
	os/windows/InjLib/Inject.c \
	os/windows/InjLib/Inject.h \
	os/windows/InjLib/LenDis.c \
	os/windows/InjLib/LenDis.h \
	os/windows/InjLib/Remote.c \
	os/windows/InjLib/Remote.h \
	os/windows/InjLib/Struct.h

ezinject_LDADD += libos_windows.la libos_windows_util.la libwindows_injlib.la
endif

# ---------------------------------------------------------------------------
# ezinject main sources
# ---------------------------------------------------------------------------
ezinject_SOURCES += \
	ezinject.c \
	ezinject.h \
	ezinject_arch.h \
	ezinject_common.h \
	ezinject_compat.h \
	ezinject_injcode.h \
	ezinject_module.h \
	dlfcn_compat.h

# Injection code - handle HPPA special case separately
if EZ_ARCH_HPPA
# For HPPA: compile to .s, patch with PHP, assemble patched .s
CLEANFILES += ezinject_injcode.s ezinject_injcode_patched.s

ezinject_injcode.s: $(srcdir)/ezinject_injcode.c config.h
	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) \
		$(INJCODE_CFLAGS) -S $(srcdir)/ezinject_injcode.c -o $@

ezinject_injcode_patched.s: ezinject_injcode.s $(srcdir)/hppa_patch_calls.sh
	$(SHELL) $(srcdir)/hppa_patch_calls.sh ezinject_injcode.s ezinject_injcode_patched.s

nodist_ezinject_SOURCES = ezinject_injcode_patched.s
else
ezinject_SOURCES += ezinject_injcode.c
endif

# POSIX linker flag
if EZ_TARGET_POSIX
ezinject_LDADD += $(LIBDL_LINK)
endif

# Static build
if ENABLE_STATIC
ezinject_LDFLAGS += -static
endif

# Linker flags
ezinject_LDFLAGS += $(UNDEFINED_FLAG)

# ---------------------------------------------------------------------------
# libhooker (lh) libraries - installed for out-of-tree module building
# ---------------------------------------------------------------------------
if LH_ENABLED
lib_LTLIBRARIES += liblh_ifcpu.la liblh_ifhook.la

liblh_ifcpu_la_SOURCES = crt/lh/interface/cpu/cpu_common.c
liblh_ifcpu_la_CFLAGS = $(AM_CFLAGS) -DLH_JUMP_ABS -fPIC
liblh_ifcpu_la_LIBADD =
liblh_ifcpu_la_LDFLAGS = $(UNDEFINED_FLAG) -avoid-version

liblh_ifhook_la_SOURCES = crt/lh/interface/hook/lh_hook.c
liblh_ifhook_la_CFLAGS = $(AM_CFLAGS) -DLH_JUMP_ABS -fPIC
liblh_ifhook_la_LIBADD = liblh_ifcpu.la
liblh_ifhook_la_LDFLAGS = $(UNDEFINED_FLAG) -avoid-version

if LH_CPU_ARM
liblh_ifcpu_la_SOURCES += crt/lh/interface/cpu/arm/cpu_arm.c
endif
if LH_CPU_ARM64
liblh_ifcpu_la_SOURCES += crt/lh/interface/cpu/arm64/cpu_arm64.c
endif
if LH_CPU_MIPS
liblh_ifcpu_la_SOURCES += crt/lh/interface/cpu/mips/cpu_mips.c
liblh_ifcpu_la_CFLAGS += -fPIC
endif
if LH_CPU_INTEL
liblh_ifcpu_la_SOURCES += \
	crt/lh/interface/cpu/intel/common_intel.c
if EZ_ARCH_AMD64
liblh_ifcpu_la_SOURCES += crt/lh/interface/cpu/intel/cpu_x86_64.c
endif
if EZ_ARCH_I386
liblh_ifcpu_la_SOURCES += crt/lh/interface/cpu/intel/cpu_i386.c
endif
endif

if USE_CAPSTONE
liblh_ifcpu_la_CFLAGS += $(CAPSTONE_CFLAGS)
liblh_ifcpu_la_LIBADD += $(CAPSTONE_LIBS)
liblh_ifhook_la_CFLAGS += $(CAPSTONE_CFLAGS)
liblh_ifhook_la_LIBADD += $(CAPSTONE_LIBS)
endif

endif # LH_ENABLED

# ---------------------------------------------------------------------------
# CRT convenience library (for sample shared modules)
# ---------------------------------------------------------------------------
noinst_LTLIBRARIES += libezinject_crt.la

libezinject_crt_la_SOURCES = \
	crt/crt.c crt/crt.h \
	crt/crt_user.c \
	ezinject_util.c ezinject_util.h \
	log.c log.h

libezinject_crt_la_CFLAGS = $(AM_CFLAGS) -fPIC

if EZ_TARGET_POSIX
libezinject_crt_la_SOURCES += crt/crt_posix.c
endif
if EZ_TARGET_WINDOWS
libezinject_crt_la_SOURCES += crt/crt_windows.c os/windows/util.c os/windows/util.h
endif

# Separate lib for crt_injcode.c - needs special injection code flags
noinst_LTLIBRARIES += libezinject_crt_injcode.la
libezinject_crt_injcode_la_SOURCES = crt/crt_injcode.c crt/crt_injcode.h
libezinject_crt_injcode_la_CFLAGS = $(AM_CFLAGS) $(INJCODE_CFLAGS) -fPIC

# crt_injcode.c needs special injection code flags
# (handled via libezinject_crt_injcode_la_CFLAGS above)

# ---------------------------------------------------------------------------
# Inject code special compilation flags
# ---------------------------------------------------------------------------
ezinject-ezinject_injcode.$(OBJEXT): CFLAGS = $(AM_CFLAGS) $(INJCODE_CFLAGS)

# ---------------------------------------------------------------------------
# Sample shared library modules
# ---------------------------------------------------------------------------
lib_LTLIBRARIES += libdummy.la libpyloader.la libnetapi.la

libdummy_la_SOURCES = samples/dummy/libdummy.c
libdummy_la_CFLAGS = $(AM_CFLAGS) -fPIC -D__USE_MINGW_ANSI_STDIO=0
libdummy_la_LIBADD = libezinject_crt.la libezinject_crt_injcode.la $(LIBPTHREAD_LINK)
libdummy_la_LDFLAGS = -module -avoid-version -shared $(UNDEFINED_FLAG)
if EZ_TARGET_WINDOWS
libdummy_la_LDFLAGS += -Wl,-entry=MyDllMainCRTStartup
endif
if EZ_TARGET_POSIX
if !EZ_TARGET_ANDROID
libdummy_la_LIBADD += $(LIBDL_LINK)
endif
endif

libpyloader_la_SOURCES = samples/pyloader/pyloader.c
libpyloader_la_CFLAGS = $(AM_CFLAGS) -fPIC
libpyloader_la_LIBADD = libezinject_crt.la libezinject_crt_injcode.la $(LIBPTHREAD_LINK)
libpyloader_la_LDFLAGS = -module -avoid-version -shared $(UNDEFINED_FLAG)
if EZ_TARGET_POSIX
libpyloader_la_LIBADD += $(LIBDL_LINK)
endif

libnetapi_la_SOURCES = samples/netapi/netapi.c
libnetapi_la_CFLAGS = $(AM_CFLAGS) -fPIC
libnetapi_la_LIBADD = libezinject_crt.la libezinject_crt_injcode.la
libnetapi_la_LDFLAGS = -module -avoid-version -shared $(UNDEFINED_FLAG)
if EZ_TARGET_POSIX
libnetapi_la_LIBADD += $(LIBDL_LINK)
if !EZ_TARGET_ANDROID
libnetapi_la_LIBADD += $(LIBPTHREAD_LINK)
endif
endif
if EZ_TARGET_WINDOWS
libnetapi_la_LIBADD += -lws2_32 -lpthread
endif

# C++ sample: skipped due to upstream sljit removal bug
# (libdummy.cpp references sljit_free_exec which was removed)

# ---------------------------------------------------------------------------
# Test target executables (dummy target process)
# ---------------------------------------------------------------------------

# dummy test target (used with libdummy.so)
bin_PROGRAMS += target
target_SOURCES = samples/dummy/target.c
target_CFLAGS = $(AM_CFLAGS)
target_CPPFLAGS = $(AM_CPPFLAGS)
if !EZ_TARGET_DARWIN
if !EZ_TARGET_WINDOWS
target_LDFLAGS = -Wl,--export-dynamic
endif
endif

# POSIX dl-based test target
if EZ_TARGET_POSIX
bin_PROGRAMS += target_dl
target_dl_SOURCES = samples/dummy/target_dl.c
target_dl_CFLAGS = $(AM_CFLAGS)
target_dl_CPPFLAGS = $(AM_CPPFLAGS)
target_dl_LDADD = $(LIBDL_LINK)
endif

# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------

# Install CRT object files for out-of-tree module building
install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(libdir)/ezinject/crt
	$(INSTALL_DATA) crt/.libs/libezinject_crt_injcode_la-crt_injcode.o $(DESTDIR)$(libdir)/ezinject/crt/crt_injcode.o
	$(INSTALL_DATA) crt/.libs/libezinject_crt_la-crt.o $(DESTDIR)$(libdir)/ezinject/crt/crt.o
	$(INSTALL_DATA) crt/.libs/libezinject_crt_la-crt_user.o $(DESTDIR)$(libdir)/ezinject/crt/crt_user.o
	if test -f crt/.libs/libezinject_crt_la-crt_posix.o; then \
		$(INSTALL_DATA) crt/.libs/libezinject_crt_la-crt_posix.o $(DESTDIR)$(libdir)/ezinject/crt/crt_posix.o; \
	fi
	if test -f crt/.libs/libezinject_crt_la-crt_windows.o; then \
		$(INSTALL_DATA) crt/.libs/libezinject_crt_la-crt_windows.o $(DESTDIR)$(libdir)/ezinject/crt/crt_windows.o; \
	fi
	$(INSTALL_DATA) .libs/libezinject_crt_la-ezinject_util.o $(DESTDIR)$(libdir)/ezinject/crt/ezinject_util.o
	$(INSTALL_DATA) .libs/libezinject_crt_la-log.o $(DESTDIR)$(libdir)/ezinject/crt/log.o

uninstall-hook:
	rm -f $(DESTDIR)$(libdir)/ezinject/crt/crt_injcode.o
	rm -f $(DESTDIR)$(libdir)/ezinject/crt/crt.o
	rm -f $(DESTDIR)$(libdir)/ezinject/crt/crt_user.o
	rm -f $(DESTDIR)$(libdir)/ezinject/crt/crt_posix.o
	rm -f $(DESTDIR)$(libdir)/ezinject/crt/crt_windows.o
	rm -f $(DESTDIR)$(libdir)/ezinject/crt/ezinject_util.o
	rm -f $(DESTDIR)$(libdir)/ezinject/crt/log.o
	-rmdir $(DESTDIR)$(libdir)/ezinject/crt
	-rmdir $(DESTDIR)$(libdir)/ezinject

# Install headers
ezinject_includedir = $(includedir)/ezinject
ezinject_include_HEADERS = \
	dlfcn_compat.h \
	ezinject_arch.h \
	ezinject_common.h \
	ezinject_compat.h \
	ezinject_injcode.h \
	ezinject_module.h \
	ezinject_util.h \
	ezinject.h \
	log.h

ezinject_include_HEADERS += $(top_builddir)/config.h

# Install architecture header
arch_includedir = $(includedir)/ezinject/arch
arch_include_HEADERS = $(top_srcdir)/$(EZ_ARCH_HEADER)

# Install libhooker interface header
interface_includedir = $(includedir)/ezinject/interface
interface_include_HEADERS = crt/lh/interface/if_hook.h crt/lh/interface/if_cpu.h

# ---------------------------------------------------------------------------
# pkg-config file
# ---------------------------------------------------------------------------
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ezinject.pc

# ---------------------------------------------------------------------------
# Extra distribution files
# ---------------------------------------------------------------------------
EXTRA_DIST += \
	config.h.cmake.in \
	build.sh \
	CMakeLists.txt \
	cmake/config.cmake.in \
	cmake/ezinject.cmake \
	cmake-modules/FindCAPSTONE.cmake \
	cmake-modules/LibFindMacros.cmake \
	arch/ezinject_aarch64.h \
	arch/ezinject_amd64.h \
	arch/ezinject_arm.h \
	arch/ezinject_darwin_amd64.h \
	arch/ezinject_freebsd_amd64.h \
	arch/ezinject_freebsd_i386.h \
	arch/ezinject_hppa.h \
	arch/ezinject_i386.h \
	arch/ezinject_mips.h \
	arch/ezinject_ppc32.h \
	arch/ezinject_ppc64.h \
	arch/ezinject_riscv.h \
	arch/ezinject_windows_amd64.h \
	arch/ezinject_windows_i386.h \
	os/CMakeLists.txt \
	os/android/CMakeLists.txt \
	os/darwin/CMakeLists.txt \
	os/freebsd/CMakeLists.txt \
	os/linux/CMakeLists.txt \
	os/windows/CMakeLists.txt \
	os/posix/CMakeLists.txt \
	os/windows/InjLib/CMakeLists.txt \
	os/linux/common.h \
	os/windows/util.h \
	win32_syscalls.h \
	crt/CMakeLists.txt \
	crt/lh/CMakeLists.txt \
	crt/lh/interface/CMakeLists.txt \
	crt/lh/interface/cpu/CMakeLists.txt \
	crt/lh/interface/cpu/arm/CMakeLists.txt \
	crt/lh/interface/cpu/arm64/CMakeLists.txt \
	crt/lh/interface/cpu/mips/CMakeLists.txt \
	crt/lh/interface/cpu/intel/CMakeLists.txt \
	crt/lh/interface/hook/CMakeLists.txt \
	patches/arm_mov_r0_1_bx_lr.bin \
	patches/thumb_mov_r0_1_bx_lr.bin \
	patches/x64_xor_rax_rax_ret.bin \
	samples/CMakeLists.txt \
	samples/cpp/CMakeLists.txt \
	samples/dotnetcore/CMakeLists.txt \
	samples/dummy/CMakeLists.txt \
	samples/memloader/CMakeLists.txt \
	samples/mono/CMakeLists.txt \
	samples/netapi/CMakeLists.txt \
	samples/php/CMakeLists.txt \
	samples/pyloader/CMakeLists.txt \
	samples/dummy/target.c \
	samples/dummy/target_dl.c \
	samples/dummy/libdummy.c \
	samples/pyloader/pyloader.c \
	samples/netapi/netapi.c \
	samples/netapi/calls.c \
	samples/memloader/memloader.c \
	samples/memloader/module.c \
	samples/memloader/memloader_blob.S \
	samples/cpp/libdummy.cpp \
	samples/cpp/target.cpp \
	ezinject_injcode_common.c \
	ezinject_injcode_posix_common.c \
	ezinject_injcode_windows_common.c \
	ezinject_injcode_util.c \
	ezinject_injcode_posix.c \
	ezinject_injcode_glibc.c \
	ezinject_injcode_uclibc.c \
	ezinject_injcode_windows.c \
	ezinject_injcode_posix.h \
	ezinject_injcode_windows.h \
	hppa_patch_calls.php \
	hppa_patch_calls.sh \
	crt/lh/interface/cpu/cpu_common.h \
	crt/lh/interface/cpu/intel/cpu_intel.h \
	m4/ax_check_compile_flag.m4
