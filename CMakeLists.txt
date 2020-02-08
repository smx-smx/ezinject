cmake_minimum_required(VERSION 3.0)
project(ezpatch C ASM)

#add_definitions(-fPIC)

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
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

if(CMAKE_TOOLCHAIN_FILE)
	message(STATUS "Using toolchain file: ${CMAKE_TOOLCHAIN_FILE}")
endif()

if( NOT CMAKE_BUILD_TYPE )
	set(CMAKE_BUILD_TYPE Debug)
endif()

if(CMAKE_BUILD_TYPE MATCHES Debug)
	set(DEBUG ON)
else()
	set(DEBUG OFF)
endif()

include(CheckLibraryExists)

find_library(C_LIBRARY "libc.so.0")
if(NOT C_LIBRARY)
	find_library(C_LIBRARY "libc.so.6")
endif()

if(NOT C_LIBRARY)
	message(FATAL_ERROR "libc.so not found")
endif()

find_library(DL_LIBRARY "libdl.so.0")
if(NOT DL_LIBRARY)
	find_library(DL_LIBRARY "libdl.so.2")
endif()

if(NOT DL_LIBRARY)
	message(FATAL_ERROR "libdl.so not found")
endif()

check_library_exists("${DL_LIBRARY}" "dlopen" "" HAVE_DLOPEN)
check_library_exists("${DL_LIBRARY}" "dlsym" "" HAVE_DLSYM)
if(NOT HAVE_DLOPEN OR NOT HAVE_DLSYM)
	message(FATAL_ERROR "Invalid libdl.so library")
endif()

get_filename_component(DL_LIBRARY_NAME "${DL_LIBRARY}" NAME)

find_library(DYN_LINKER "ld-uClibc.so.0")

check_library_exists("${C_LIBRARY}" "__libc_dlopen_mode" "" HAVE_LIBC_DLOPEN_MODE)
get_filename_component(C_LIBRARY_NAME "${C_LIBRARY}" NAME)

if(NOT HAVE_LIBC_DLOPEN_MODE)
	if(NOT DYN_LINKER)
		message(FATAL_ERROR "ld-uClibc.so.0 not found")
	endif()
	check_library_exists("${DYN_LINKER}" "_dl_load_shared_library" "" HAVE_DL_LOAD_SHARED_LIBRARY)
	get_filename_component(DYN_LINKER_NAME "${DYN_LINKER}" NAME)
endif()

if(NOT HAVE_LIBC_DLOPEN_MODE AND NOT HAVE_DL_LOAD_SHARED_LIBRARY)
	message(FATAL_ERROR "Unsupported C library")
endif()

#find_library(C_LIBRARY "libc.so")
#check_library_exists("${C_LIBRARY}" "__libc_dlopen_mode" "" HAVE_LIBC_DLOPEN_MODE)

include(CheckSymbolExists)
check_symbol_exists("__NR_shmget" "asm/unistd.h" HAVE_SHM_SYSCALLS)
check_symbol_exists("__NR_ipc" "asm/unistd.h" HAVE_SC_IPC)
check_symbol_exists("SHM_EXEC" "sys/shm.h" HAVE_SHM_EXEC)
check_symbol_exists("__arm__" "" EZ_ARCH_ARM)
check_symbol_exists("__i386__" "" EZ_ARCH_I386)
check_symbol_exists("__amd64__" "" EZ_ARCH_AMD64)
check_symbol_exists("__mips__" "" EZ_ARCH_MIPS)

if(NOT HAVE_SHM_SYSCALLS AND NOT HAVE_SC_IPC)
	message(FATAL_ERROR "Unsupported system")
endif()

if(EZ_ARCH_I386 OR EZ_ARCH_AMD64)
	set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake-modules/")
	if(NOT CAPSTONE_INCLUDE_DIRS AND NOT CAPSTONE_LIBRARIES)
		find_package(CAPSTONE REQUIRED)
	endif()
include_directories(${CAPSTONE_INCLUDE_DIRS})
endif()

if(EZ_ARCH_MIPS)
	# TODO: check headers?
	set(UCLIBC_OLD TRUE)
endif()

configure_file(
	config.h.in
	${CMAKE_BINARY_DIR}/config.h
)

add_library(util
	util.c
	elfparse.c
)

add_executable(ezpatch
	elfparse.c
	ezpatch.c
)
target_link_libraries(ezpatch util)

function(add_ezinject_library target sources)
	list(APPEND sources ${CMAKE_SOURCE_DIR}/crt/crt.c)
	if(DEBUG)
		list(APPEND sources ${CMAKE_SOURCE_DIR}/util.c)
	endif()

	add_library(${target} SHARED ${sources})

	target_link_libraries(${target}
		lh_ifcpu
		lh_sljitmod
		lh_hook_linux
	)
endfunction()

add_subdirectory(crt)
add_subdirectory(samples)


add_executable(ezinject
	ezinject.c
	ezinject_injcode.c
	util.c
)

# -fno-toplevel-reorder: keep order of code as it was written
# -fno-stack-protector: remove stack cookie checks
# -fno-pic: remove calls to __x86_get_pc_thunk_ax (PIC
# -nostdlib: this code doesn't use any library
# -frame-pointer: don't save stack frames
set_source_files_properties(ezinject_injcode.c PROPERTIES COMPILE_FLAGS "-fno-toplevel-reorder -fno-stack-protector -fno-pic -nostdlib -fomit-frame-pointer")
target_link_libraries(ezinject dl lh_elf)
