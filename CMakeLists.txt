cmake_minimum_required(VERSION 3.0)
project(ezpatch C ASM)

include_directories(
	${CMAKE_SOURCE_DIR}
	${CMAKE_BINARY_DIR}
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

include(CheckSymbolExists)

check_symbol_exists("__arm__" "" EZ_ARCH_ARM)
check_symbol_exists("__i386__" "" EZ_ARCH_I386)
check_symbol_exists("__amd64__" "" EZ_ARCH_AMD64)
check_symbol_exists("__mips__" "" EZ_ARCH_MIPS)

configure_file(
	config.h.in
	${CMAKE_BINARY_DIR}/config.h
)

add_library(common
	util.c
	elfparse.c
)

add_executable(target target.c)

add_executable(ezpatch
	elfparse.c
	ezpatch.c
)
target_link_libraries(ezpatch common)

add_executable(ezinject
	ezinject.c
	ezinject_injcode.c
)


set_source_files_properties(ezinject_injcode.c PROPERTIES COMPILE_FLAGS -fno-toplevel-reorder)
target_link_libraries(ezinject common dl rt)

add_library(dummy SHARED libdummy.c)
