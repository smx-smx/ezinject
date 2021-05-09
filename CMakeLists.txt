# 3.14 requirement: https://cmake.org/cmake/help/latest/policy/CMP0083.html
cmake_minimum_required(VERSION 3.14)
project(ezpatch C ASM)
enable_language(CXX OPTIONAL)
enable_testing()

add_definitions(-fPIC)

if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
	set(EZ_TARGET_LINUX TRUE)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD")
	set(EZ_TARGET_FREEBSD TRUE)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
	SET(CMAKE_FIND_LIBRARY_PREFIXES "" "lib")
	SET(CMAKE_FIND_LIBRARY_SUFFIXES ".lib" ".dll")
	set(EZ_TARGET_WINDOWS TRUE)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
	SET(CMAKE_FIND_LIBRARY_PREFIXES "" "lib")
	SET(CMAKE_FIND_LIBRARY_SUFFIXES "" ".a" ".dylib")
	set(EZ_TARGET_DARWIN TRUE)
	
	message(STATUS "SDK Path: ${CMAKE_OSX_SYSROOT}")
else()
	message(FATAL_ERROR "Unsupported OS ${CMAKE_SYSTEM_NAME}")
endif()

if(NOT EZ_TARGET_WINDOWS AND NOT EZ_TARGET_DARWIN)
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-export-dynamic")
endif()

include(CheckIncludeFile)
check_include_file(sys/shm.h HAVE_SYS_SHM_H)

include(CheckSymbolExists)
check_symbol_exists("__NR_shmget" "asm/unistd.h" HAVE_SHM_SYSCALLS)
check_symbol_exists("__NR_ipc" "asm/unistd.h" HAVE_SC_IPC)
check_symbol_exists("SHM_EXEC" "sys/shm.h" HAVE_SHM_EXEC)
check_symbol_exists("strsignal" "string.h" HAVE_STRSIGNAL)
check_symbol_exists("RTLD_NOLOAD" "dlfcn.h" HAVE_RTLD_NOLOAD)
check_symbol_exists("__arm__" "" EZ_ARCH_ARM)
check_symbol_exists("__aarch64__" "" EZ_ARCH_ARM64)
check_symbol_exists("__i386__" "" EZ_ARCH_I386)
check_symbol_exists("__amd64__" "" EZ_ARCH_AMD64)
check_symbol_exists("__mips__" "" EZ_ARCH_MIPS)
check_symbol_exists("__ANDROID__" "" EZ_TARGET_ANDROID)

if(EZ_TARGET_LINUX OR EZ_TARGET_FREEBSD OR EZ_TARGET_DARWIN)
	set(EZ_TARGET_POSIX TRUE)
endif()

if(EZ_TARGET_LINUX)
	if(NOT EZ_TARGET_ANDROID)
		add_definitions(-Wl,--no-undefined)
	else()
		if(NOT DEFINED USE_ANDROID_ASHMEM)
			set(USE_ANDROID_ASHMEM ON)
		endif()
	endif()
endif()

set(USING_GNU_LD FALSE)

if(APPLE AND (CMAKE_C_COMPILER_ID STREQUAL "Clang" OR CMAKE_C_COMPILER_ID STREQUAL "AppleClang"))
elseif(MSVC)
else()
	# assume gcc + binutils
	# $TODO: could use CheckLinkerFlag in CMake 3.18
	set(USING_GNU_LD TRUE)
endif()

include_directories(
	${CMAKE_SOURCE_DIR}
	${CMAKE_BINARY_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}/crt/lh
)
add_definitions(
	-DSLJIT_CONFIG_AUTO
	-DSLJIT_DEBUG=0
	-DLH_JUMP_ABS
)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror=implicit-function-declaration")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

if(CMAKE_TOOLCHAIN_FILE)
	message(STATUS "Using toolchain file: ${CMAKE_TOOLCHAIN_FILE}")
endif()

if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Debug)
endif()

if(NOT DEFINED DEBUG)
	if(CMAKE_BUILD_TYPE MATCHES Debug)
		set(DEBUG ON)
	elseif()
		set(DEBUG OFF)
	endif()
endif()

include(CheckLibraryExists)

set(REQUIRES_LIBPTHREAD REQUIRED)
set(REQUIRES_LIBDL REQUIRED)

if(EZ_TARGET_ANDROID)
	set(prefix ${CMAKE_SYSROOT}/usr/lib/${ANDROID_TOOLCHAIN_NAME})
	# remove last dash
	string(FIND "${prefix}" "-" index REVERSE)
	string(SUBSTRING "${prefix}" 0 ${index}	prefix)

	set(libs_path ${prefix}/${ANDROID_NATIVE_API_LEVEL})
	list(APPEND CMAKE_LIBRARY_PATH ${libs_path})
	set(CMAKE_FIND_USE_CMAKE_PATH TRUE)
endif()

if(EZ_TARGET_ANDROID OR EZ_TARGET_WINDOWS)
	set(REQUIRES_LIBPTHREAD "")
endif()

if(EZ_TARGET_DARWIN)
	set(REQUIRES_LIBDL "")
endif()

set(EXTRA_SEARCH_PATHS "")
set(C_LIBRARY_NAMES "")

if(EZ_TARGET_LINUX)
	list(APPEND C_LIBRARY_NAMES
		# glibc
		libc.so.6
		# uClibc
		libc.so.0
		# fallback
		libc.so
	)
elseif(EZ_TARGET_FREEBSD)
	list(APPEND C_LIBRARY_NAMES
		libc.so.7
	)
elseif(EZ_TARGET_DARWIN)
	list(APPEND C_LIBRARY_NAMES
		libsystem_kernel.dylib
	)
	list(APPEND EXTRA_SEARCH_PATHS "/usr/lib/system")
elseif(EZ_TARGET_WINDOWS)
	list(APPEND C_LIBRARY_NAMES
		ntdll.dll
	)
	list(APPEND EXTRA_SEARCH_PATHS "$ENV{SystemRoot}\\System32")
endif()

find_library(C_LIBRARY
	NAMES ${C_LIBRARY_NAMES}
	PATHS ${EXTRA_SEARCH_PATHS}
	REQUIRED
)
get_filename_component(C_LIBRARY_NAME "${C_LIBRARY}" NAME)

set(DL_LIBRARY_NAMES "")
if(EZ_TARGET_LINUX OR EZ_TARGET_FREEBSD)
	list(APPEND DL_LIBRARY_NAMES
		# glibc
		libdl.so.2
		# uClibc
		libdl.so.0
		# fallback
		libdl.so
	)
elseif(EZ_TARGET_WINDOWS)
	list(APPEND DL_LIBRARY_NAMES
		# implements LoadLibraryA
		Kernel32.dll
	)
endif()

if(NOT ${REQUIRES_LIBDL} STREQUAL "")
	find_library(DL_LIBRARY
		NAMES ${DL_LIBRARY_NAMES}
		PATHS ${EXTRA_SEARCH_PATHS}
		${REQUIRES_LIBDL}
	)
	get_filename_component(DL_LIBRARY_NAME "${DL_LIBRARY}" NAME)
elseif(EZ_TARGET_DARWIN)
	# NOTE: this can be a fake library
	# it mignt not exist and is intercepted by dyld
	# Darwin physically exposed libdl through dyld
	# however, target processes have a virtual mapping called
	# libdyld.dylib which seems to be a remapped dyld, containing the actual symbols
	set(DL_LIBRARY_NAME "libdl.dylib")
else()
	message(FATAL_ERROR "Unsupported platform")
endif()

find_library(PTHREAD_LIBRARY
	PATHS ${EXTRA_SEARCH_PATHS}
	NAMES
		# darwin
		libsystem_pthread
		# uClibc
		libpthread.so.0
		# fallback
		libpthread.so
	${REQUIRES_LIBPTHREAD}
)

if(EZ_TARGET_ANDROID)
	# these platforms implement pthreads in libc
	set(PTHREAD_LIBRARY_NAME ${C_LIBRARY_NAME})
elseif(EZ_TARGET_DARWIN)
	# libpthread is also a fake library provided by /usr/lib/system/libsystem_pthread.dylib
	set(PTHREAD_LIBRARY_NAME "libpthread.dylib")
elseif(EZ_TARGET_WINDOWS)
	# this is actually kernel32.dll
	set(PTHREAD_LIBRARY_NAME ${DL_LIBRARY_NAME})
else()
	get_filename_component(PTHREAD_LIBRARY_NAME "${PTHREAD_LIBRARY}" NAME)
endif()

if(EZ_ARCH_ARM)
	if(USE_ARM_THUMB)
		add_definitions(-mthumb)
	else()
		add_definitions(-marm)
	endif()
endif()

if(EZ_TARGET_DARWIN)
	# we need full names on Darwin
	set(C_LIBRARY_NAME ${C_LIBRARY})
endif()

macro(find_uclibc)
	find_library(DYN_LINKER
		NAMES ld-uClibc.so.0
		REQUIRED
	)	
	get_filename_component(DYN_LINKER_NAME "${DYN_LINKER}" NAME)
endmacro()

macro(export_var var)
	if(DEFINED ${var})
		set(${var} "${${var}}" PARENT_SCOPE)
	endif()
endmacro()

function(libc_autodetect)
	if(EZ_TARGET_WINDOWS)
		check_library_exists("${C_LIBRARY}" "LdrLoadDll" "" HAVE_LDR_LOAD_DLL)
		check_library_exists("${DL_LIBRARY}" "LoadLibraryA" "" HAVE_LOADLIBRARY)
		if(NOT HAVE_LDR_LOAD_DLL)
			message(FATAL_ERROR "Invalid or unsupported ntdll.dll")
		endif()
		if(NOT HAVE_LOADLIBRARY)
			message(FATAL_ERROR "Invalid or unsupported kernel32.dll")
		endif()

		export_var(HAVE_LDR_LOAD_DLL)
		export_var(HAVE_LOADLIBRARY)
		return()
	endif()

	check_library_exists("${C_LIBRARY}" "__libc_dlopen_mode" "" HAVE_LIBC_DLOPEN_MODE)
	export_var(HAVE_LIBC_DLOPEN_MODE)

	if(EZ_TARGET_LINUX
	AND NOT HAVE_LIBC_DLOPEN_MODE)
		find_uclibc()
		export_var(DYN_LINKER_NAME)
		check_library_exists("${DYN_LINKER}" "_dl_load_shared_library" "" HAVE_DL_LOAD_SHARED_LIBRARY)
	endif()


	check_library_exists("${C_LIBRARY}" "dlopen" "" HAVE_DLOPEN)
	check_library_exists("${C_LIBRARY}" "dlopen" "" HAVE_DLSYM)
	if(HAVE_DLOPEN AND HAVE_DLSYM)
		set(HAVE_LIBDL_IN_LIBC TRUE)
		export_var(HAVE_LIBDL_IN_LIBC)
	else()
		unset(HAVE_DLOPEN CACHE)
		unset(HAVE_DLSYM CACHE)
	endif()

	check_library_exists("${DL_LIBRARY}" "dlopen" "" HAVE_DLOPEN)
	check_library_exists("${DL_LIBRARY}" "dlsym" "" HAVE_DLSYM)

	if(NOT HAVE_DLOPEN OR NOT HAVE_DLSYM)
		message(FATAL_ERROR "Invalid libdl.so library")
	endif()

	export_var(HAVE_DLOPEN)
	export_var(HAVE_DLSYM)

	if(EZ_TARGET_FREEBSD)
		if(EZ_ARCH_I386)
			set(lib_name ld-elf32.so.1)
		elseif(EZ_ARCH_AMD64)
			set(lib_name ld-elf.so.1)
		else()
			message(FATAL_ERROR "Unsupported FreeBSD architecture")
		endif()
		find_library(DYN_LINKER
			PATHS /libexec
			NAMES ${lib_name}
			REQUIRED
		)	
		set(DYN_LINKER_NAME "${DYN_LINKER}")
		export_var(DYN_LINKER_NAME)
	elseif(EZ_TARGET_DARWIN)
		# libdyld.dylib is a virtual library
		set(DYN_LINKER_NAME "libdyld.dylib")
		export_var(DYN_LINKER_NAME)
	endif()

	if(NOT EZ_TARGET_ANDROID
	AND NOT HAVE_LIBC_DLOPEN_MODE
	AND NOT HAVE_DL_LOAD_SHARED_LIBRARY
	AND NOT HAVE_LIBDL_IN_LIBC
	AND NOT EZ_TARGET_DARWIN
	)
		message(FATAL_ERROR "Unsupported C library")
	endif()

	if(EZ_ARCH_MIPS)
		# TODO: check headers?
		set(UCLIBC_OLD TRUE)
		export_var(UCLIBC_OLD)
	endif()
endfunction()

if(NOT DEFINED EZ_LIBC)
	libc_autodetect()
elseif(EZ_LIBC STREQUAL "glibc")
	set(HAVE_LIBC_DLOPEN_MODE TRUE)
elseif(EZ_LIBC STREQUAL "uclibc")
	find_uclibc()
	set(HAVE_DL_LOAD_SHARED_LIBRARY TRUE)
	if(EZ_LIBC_VARIANT STREQUAL "old")
		set(UCLIBC_OLD TRUE)
	endif()
elseif(EZ_LIBC STREQUAL "bionic")
	set(DYN_LINKER_NAME "/system/bin/linker")
	if(EZ_LIBC_VARIANT STREQUAL "android-2")
	elseif(EZ_LIBC_VARIANT STREQUAL "android-5")
		# android 5+ requires -fPIE
		set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
	elseif(EZ_LIBC_VARIANT STREQUAL "android-10")
		set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
		if(EZ_ARCH_ARM64)
			set(DYN_LINKER_NAME "/apex/com.android.runtime/bin/linker64")
		else()
			set(DYN_LINKER_NAME "/apex/com.android.runtime/bin/linker")
		endif()
	else()
		message(FATAL_ERROR "Unsupported libc variant ${EZ_LIBC_VARIANT}")
	endif()
endif()

if( NOT EZ_TARGET_WINDOWS
	AND NOT HAVE_SHM_SYSCALLS
	AND NOT HAVE_SC_IPC
	AND NOT USE_ANDROID_ASHMEM
	AND NOT HAVE_LIBDL_IN_LIBC
	AND NOT EZ_TARGET_DARWIN
)
	message(FATAL_ERROR "Unsupported system")
endif()

if(EZ_ARCH_I386 OR EZ_ARCH_AMD64 OR (EZ_ARCH_ARM AND USE_ARM_THUMB))
	# for ARM, this is true only on Thumb
	set(HAVE_CPU_VLE ON)
endif()

if(HAVE_CPU_VLE)
	if(NOT CAPSTONE_PREFIX)
		set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake-modules/")
		if(NOT CAPSTONE_INCLUDE_DIRS AND NOT CAPSTONE_LIBRARIES)
			find_package(CAPSTONE REQUIRED)
		endif()
		include_directories(${CAPSTONE_INCLUDE_DIRS})
	else()
		find_library(
				CAPSTONE_LIBRARIES REQUIRED
				NO_DEFAULT_PATH
				PATHS ${CAPSTONE_PREFIX}/lib
				NAMES libcapstone.a capstone
				CMAKE_FIND_ROOT_PATH_BOTH 
		)
		include_directories(${CAPSTONE_PREFIX}/include)
	endif()
endif()

if(EZ_TARGET_FREEBSD OR EZ_TARGET_DARWIN OR EZ_TARGET_WINDOWS)
	set(USE_SHM FALSE)
else()
	set(USE_SHM TRUE)
endif()

configure_file(
	config.h.in
	${CMAKE_BINARY_DIR}/config.h
)

function(add_ezinject_library target)
	cmake_parse_arguments(LIB "USE_LH;USE_LOG" "" "SOURCES" ${ARGN})

	set(sources "${LIB_SOURCES}")

	if(NOT EZ_TARGET_WINDOWS)
		list(APPEND sources
			${CMAKE_SOURCE_DIR}/ezinject_compat.c
		)
	endif()

	list(APPEND sources
		${CMAKE_SOURCE_DIR}/crt/crt.c
		${CMAKE_SOURCE_DIR}/crt/crt_user.c
		${CMAKE_SOURCE_DIR}/ezinject_util.c
	)

	if(EZ_TARGET_POSIX)
		list(APPEND sources
			${CMAKE_SOURCE_DIR}/crt/crt_posix.c
		)
	elseif(EZ_TARGET_WINDOWS)
		list(APPEND sources
			${CMAKE_SOURCE_DIR}/crt/crt_windows.c
			${CMAKE_SOURCE_DIR}/os/windows/util.c
		)
	endif()

	set(moduledefs "MODULE_NAME=\"${target}\"")
	if(LIB_USE_LOG)
		list(APPEND moduledefs "LOG_USE_FILE")
	endif()

	foreach(source_file IN LISTS sources)
		set_source_files_properties("${source_file}" PROPERTIES COMPILE_DEFINITIONS "${moduledefs}")
	endforeach()

	add_library(${target} SHARED ${sources})

	if(NOT REQUIRES_LIBPTHREAD STREQUAL "")
		target_link_libraries(${target} pthread)
	endif()

	if(LIB_USE_LH)
		# force a dependency on the hook library
		# even if user code doesn't use it
		if(USING_GNU_LD)
			target_link_options(${target} PUBLIC
				-Wl,--whole-archive
					$<TARGET_FILE:lh_hook_linux>
				-Wl,--no-whole-archive
			)
		endif()
		target_link_libraries(${target}
			lh_ifcpu
			lh_sljitmod
			lh_hook_linux
		)
	endif()

	if(EZ_TARGET_ANDROID AND USE_ANDROID_ASHMEM)
		target_link_options(${target} PUBLIC
			-Wl,--whole-archive $<TARGET_FILE:ashmem> -Wl,--no-whole-archive
		)
	endif()
endfunction()

set(os_sources "")
if(EZ_TARGET_POSIX)
	list(APPEND os_sources
		os/posix/remote.c
		os/posix/inject.c
	)
	if(EZ_TARGET_LINUX)
		list(APPEND os_sources
			os/linux/remote.c
			os/linux/util.c
		)

		# Android with ashmem + mmap
		if(EZ_TARGET_ANDROID AND USE_ANDROID_ASHMEM)
			list(APPEND os_sources
				os/android/inject.c
			)
		# SysV IPC with executable SHM
		else()
			list(APPEND os_sources
				os/linux/inject.c
			)
		endif()

		# bionic
		if(EZ_TARGET_ANDROID)
			list(APPEND os_sources
				os/android/libc_bionic.c
				elfparse.c
			)
		# glibc
		elseif(HAVE_LIBC_DLOPEN_MODE)
			list(APPEND os_sources
				os/linux/libc_glibc.c
			)
		# uClibc
		elseif(HAVE_DL_LOAD_SHARED_LIBRARY)
			list(APPEND os_sources
				os/linux/libc_uclibc.c
			)
		endif()
	elseif(EZ_TARGET_FREEBSD)
		list(APPEND os_sources
			os/freebsd/remote.c
			os/freebsd/inject.c
			os/freebsd/util.c
			os/freebsd/libc_freebsd.c
		)
	elseif(EZ_TARGET_DARWIN)
		list(APPEND os_sources
			os/darwin/remote.c
			os/darwin/inject.c
			os/darwin/util.c
			os/darwin/libc_darwin.c
		)
	endif()
elseif(EZ_TARGET_WINDOWS)
	list(APPEND os_sources
		os/windows/remote.c
		os/windows/inject.c
		os/windows/util.c
		os/windows/libc_windows.c
	)
endif()

# TODO: cross platform
if(EZ_TARGET_LINUX)
	add_executable(ezpatch
		elfparse.c
		ezpatch.c
		elfparse.c
		ezinject_util.c
		os/linux/util.c
	)
endif()

set(ezinject_sources
	ezinject.c
	ezinject_injcode.c
	ezinject_util.c
	${os_sources}
)

# not android, or android without ashmem
if((EZ_TARGET_ANDROID AND NOT USE_ANDROID_ASHMEM) OR NOT HAVE_SYS_SHM_H
AND NOT EZ_TARGET_WINDOWS
AND NOT EZ_TARGET_DARWIN)
	list(APPEND ezinject_sources ezinject_compat.c)
endif()

add_executable(ezinject ${ezinject_sources})


if(EZ_TARGET_FREEBSD)
	target_link_libraries(ezinject procstat)
endif()

if(ENABLE_STATIC)
	target_link_options(ezinject PUBLIC -static)
endif()

include(CheckCCompilerFlag)
check_c_compiler_flag("-mno-stack-arg-probe" HAVE_STACK_ARG_PROBE)

set(injcode_cflags "-Os -fno-jump-tables -fno-stack-check -fno-stack-protector -fno-pic -nostdlib -fomit-frame-pointer -ffreestanding")
if(HAVE_STACK_ARG_PROBE)
	set(injcode_cflags "${injcode_cflags} -mno-stack-arg-probe")
endif()

# -fno-stack-protector: remove stack cookie checks
# -fno-pic: remove calls to __x86_get_pc_thunk_ax
# -nostdlib: this code doesn't use any library
# -fomit-frame-pointer: don't save stack frames
# -ffreestanding: don't assume libc functions exist
# -fno-stack-check,-mno-stack-arg-probe: don't emit ___chkstk_ms calls
set_source_files_properties(ezinject_injcode.c PROPERTIES COMPILE_FLAGS "${injcode_cflags}")
target_link_libraries(ezinject dl)

if(EZ_TARGET_ANDROID AND USE_ANDROID_ASHMEM)
	add_subdirectory(android-shmem)
	add_dependencies(ezinject ashmem)
	target_link_options(ezinject PUBLIC
		-Wl,--whole-archive $<TARGET_FILE:ashmem> -Wl,--no-whole-archive
	)
endif()

add_subdirectory(crt)
add_subdirectory(samples)
add_subdirectory(test)