cmake_minimum_required(VERSION 3.0)
project(ezpatch C ASM)

add_definitions(-fPIC)

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

include(CheckSymbolExists)

check_symbol_exists("__arm__" "" EZ_ARCH_ARM)
check_symbol_exists("__i386__" "" EZ_ARCH_I386)
check_symbol_exists("__amd64__" "" EZ_ARCH_AMD64)
check_symbol_exists("__mips__" "" EZ_ARCH_MIPS)

if(EZ_ARCH_I386 OR EZ_ARCH_AMD64)
	set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake-modules/")
	if(NOT CAPSTONE_INCLUDE_DIRS AND NOT CAPSTONE_LIBRARIES)
		find_package(CAPSTONE REQUIRED)
	endif()
include_directories(${CAPSTONE_INCLUDE_DIRS})
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

add_executable(ezinject
	ezinject.c
	ezinject_injcode.c
	util.c
)

set_source_files_properties(ezinject_injcode.c PROPERTIES COMPILE_FLAGS -fno-toplevel-reorder)
target_link_libraries(ezinject dl)

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
