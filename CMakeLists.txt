# 3.14 requirement: https://cmake.org/cmake/help/latest/policy/CMP0083.html
cmake_minimum_required(VERSION 3.14)
project(ezpatch C ASM)
enable_language(CXX OPTIONAL)

include(CheckPIESupported)
check_pie_supported()

add_definitions(-fPIC)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-export-dynamic")

if(NOT ANDROID)
	add_definitions(-Wl,--no-undefined)
else()
	if(NOT DEFINED USE_ANDROID_ASHMEM)
		set(USE_ANDROID_ASHMEM ON)
	endif()
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

if(ANDROID)
	set(prefix ${CMAKE_SYSROOT}/usr/lib/${ANDROID_TOOLCHAIN_NAME})
	# remove last dash
	string(FIND "${prefix}" "-" index REVERSE)
	string(SUBSTRING "${prefix}" 0 ${index}	prefix)

	set(libs_path ${prefix}/${ANDROID_NATIVE_API_LEVEL})
	list(APPEND CMAKE_LIBRARY_PATH ${libs_path})
	set(CMAKE_FIND_USE_CMAKE_PATH TRUE)

	set(REQUIRES_LIBPTHREAD "")
endif()

find_library(C_LIBRARY
	NAMES
		libc.so.6
		libc.so.0
		libc.so
	REQUIRED
)
get_filename_component(C_LIBRARY_NAME "${C_LIBRARY}" NAME)

find_library(DL_LIBRARY
	NAMES
		libdl.so.2
		libdl.so.0
		libdl.so
	REQUIRED
)
get_filename_component(DL_LIBRARY_NAME "${DL_LIBRARY}" NAME)

find_library(PTHREAD_LIBRARY
	NAMES
		libpthread.so
		libpthread.so.0
	${REQUIRES_LIBPTHREAD}
)

if(ANDROID)
	# android implements pthreads in libc
	set(PTHREAD_LIBRARY_NAME ${C_LIBRARY_NAME})
else()
	get_filename_component(PTHREAD_LIBRARY_NAME "${PTHREAD_LIBRARY}" NAME)
endif()


include(CheckSymbolExists)
check_symbol_exists("__NR_shmget" "asm/unistd.h" HAVE_SHM_SYSCALLS)
check_symbol_exists("__NR_ipc" "asm/unistd.h" HAVE_SC_IPC)
check_symbol_exists("SHM_EXEC" "sys/shm.h" HAVE_SHM_EXEC)
check_symbol_exists("RTLD_NOLOAD" "dlfcn.h" HAVE_RTLD_NOLOAD)
check_symbol_exists("__arm__" "" EZ_ARCH_ARM)
check_symbol_exists("__i386__" "" EZ_ARCH_I386)
check_symbol_exists("__amd64__" "" EZ_ARCH_AMD64)
check_symbol_exists("__mips__" "" EZ_ARCH_MIPS)
check_symbol_exists("__ANDROID__" "" EZ_TARGET_ANDROID)

if(NOT HAVE_SHM_SYSCALLS AND NOT HAVE_SC_IPC AND NOT USE_ANDROID_ASHMEM)
	message(FATAL_ERROR "Unsupported system")
endif()

macro(find_uclibc)
	find_library(DYN_LINKER
		NAMES ld-uClibc.so.0
		REQUIRED
	)	
	get_filename_component(DYN_LINKER_NAME "${DYN_LINKER}" NAME)
endmacro()

macro(libc_autodetect)
	check_library_exists("${DL_LIBRARY}" "dlopen" "" HAVE_DLOPEN)
	check_library_exists("${DL_LIBRARY}" "dlsym" "" HAVE_DLSYM)
	if(NOT HAVE_DLOPEN OR NOT HAVE_DLSYM)
		message(FATAL_ERROR "Invalid libdl.so library")
	endif()

	check_library_exists("${C_LIBRARY}" "__libc_dlopen_mode" "" HAVE_LIBC_DLOPEN_MODE)

	if(NOT HAVE_LIBC_DLOPEN_MODE AND NOT ANDROID)
		find_uclibc()
		check_library_exists("${DYN_LINKER}" "_dl_load_shared_library" "" HAVE_DL_LOAD_SHARED_LIBRARY)
	endif()

	if(NOT ANDROID
	AND NOT HAVE_LIBC_DLOPEN_MODE
	AND NOT HAVE_DL_LOAD_SHARED_LIBRARY
	)
		message(FATAL_ERROR "Unsupported C library")
	endif()

	if(EZ_ARCH_MIPS)
		# TODO: check headers?
		set(UCLIBC_OLD TRUE)
	endif()
endmacro()

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
		set(HAVE_ANDROID_GINGERBREAD TRUE)
	elseif(EZ_LIBC_VARIANT STREQUAL "android-5")
		# android 5+ requires -fPIE
		set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
	elseif(EZ_LIBC_VARIANT STREQUAL "android-10")
		set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
		set(DYN_LINKER_NAME "/apex/com.android.runtime/bin/linker")
	else()
		message(FATAL_ERROR "Unsupported libc variant ${EZ_LIBC_VARIANT}")
	endif()
endif()

if(EZ_ARCH_I386 OR EZ_ARCH_AMD64)
	set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake-modules/")
	if(NOT CAPSTONE_INCLUDE_DIRS AND NOT CAPSTONE_LIBRARIES)
		find_package(CAPSTONE REQUIRED)
	endif()
include_directories(${CAPSTONE_INCLUDE_DIRS})
endif()

include(CheckIncludeFile)
check_include_file(sys/shm.h HAVE_SYS_SHM_H)


configure_file(
	config.h.in
	${CMAKE_BINARY_DIR}/config.h
)

add_executable(ezpatch
	elfparse.c
	ezpatch.c
	util.c
	elfparse.c
)

function(add_ezinject_library target)
	cmake_parse_arguments(LIB "USE_LH;USE_LOG" "" "SOURCES" ${ARGN})

	set(sources "${LIB_SOURCES}")

	list(APPEND sources
		${CMAKE_SOURCE_DIR}/ezinject_compat.c
		${CMAKE_SOURCE_DIR}/crt/crt.c
		${CMAKE_SOURCE_DIR}/crt/crt_user.c
		${CMAKE_SOURCE_DIR}/util.c
	)

	if(DEBUG)
		list(APPEND sources ${CMAKE_SOURCE_DIR}/util.c)
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

set(ezinject_sources
	ezinject.c
	ezinject_injcode.c
	util.c
)

# not android, or android without ashmem
if(NOT EZ_TARGET_ANDROID OR NOT USE_ANDROID_ASHMEM)
	if(NOT HAVE_SYS_SHM_H)
		list(APPEND ezinject_sources ezinject_compat.c)
	endif()
endif()

if(HAVE_LIBC_DLOPEN_MODE)
	list(APPEND ezinject_sources ezinject_libc_glibc.c)
elseif(HAVE_DL_LOAD_SHARED_LIBRARY)
	list(APPEND ezinject_sources ezinject_libc_uclibc.c)
elseif(EZ_TARGET_ANDROID)
	list(APPEND ezinject_sources ezinject_libc_android_gingerbread.c)
endif()

add_executable(ezinject ${ezinject_sources})

if(ENABLE_STATIC)
	target_link_options(ezinject PUBLIC -static)
endif()

# -fno-toplevel-reorder: keep order of code as it was written
# -fno-stack-protector: remove stack cookie checks
# -fno-pic: remove calls to __x86_get_pc_thunk_ax
# -nostdlib: this code doesn't use any library
# -fomit-frame-pointer: don't save stack frames
# -ffreestanding: don't assume libc functions exist
set_source_files_properties(ezinject_injcode.c PROPERTIES COMPILE_FLAGS "-Os -fno-toplevel-reorder -fno-stack-protector -fno-pic -nostdlib -fomit-frame-pointer -ffreestanding")
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
