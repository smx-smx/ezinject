set(USING_GNU_LD FALSE)

if(APPLE AND (CMAKE_C_COMPILER_ID STREQUAL "Clang" OR CMAKE_C_COMPILER_ID STREQUAL "AppleClang"))
elseif(MSVC)
else()
	# assume gcc + binutils
	# $TODO: could use CheckLinkerFlag in CMake 3.18
	set(USING_GNU_LD TRUE)
endif()

if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
	set(EZ_TARGET_LINUX TRUE)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD")
	set(EZ_TARGET_FREEBSD TRUE)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
	SET(CMAKE_FIND_LIBRARY_PREFIXES "" "lib")
	SET(CMAKE_FIND_LIBRARY_SUFFIXES ".lib" ".dll" ".a")
	if(NOT CMAKE_HOST_WIN32)
		set(CMAKE_LINK_LIBRARY_SUFFIX "")
	endif()
	string(APPEND CMAKE_EXE_LINKER_FLAGS " -static-libgcc")
	string(APPEND CMAKE_SHARED_LINKER_FLAGS " -static-libgcc")
	set(EZ_TARGET_WINDOWS TRUE)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
	SET(CMAKE_FIND_LIBRARY_PREFIXES "" "lib")
	SET(CMAKE_FIND_LIBRARY_SUFFIXES "" ".a" ".dylib")
	set(EZ_TARGET_DARWIN TRUE)

	message(STATUS "SDK Path: ${CMAKE_OSX_SYSROOT}")
else()
	message(FATAL_ERROR "Unsupported OS ${CMAKE_SYSTEM_NAME}")
endif()

include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckCSourceCompiles)
include(CheckLibraryExists)

check_symbol_exists("PSR_T_BIT" "asm/ptrace.h" HAVE_PSR_T_BIT)
check_symbol_exists("strsignal" "string.h" HAVE_STRSIGNAL)

check_c_source_compiles("
#define _GNU_SOURCE
#include <dlfcn.h>
int main(){
	int x = RTLD_NOLOAD;
	return 0;
}

" HAVE_RTLD_NOLOAD)

check_symbol_exists("__arm__" "" EZ_ARCH_ARM)
check_symbol_exists("__aarch64__" "" EZ_ARCH_ARM64)
check_symbol_exists("__i386__" "" EZ_ARCH_I386)
check_symbol_exists("__amd64__" "" EZ_ARCH_AMD64)
check_symbol_exists("__mips__" "" EZ_ARCH_MIPS)
check_symbol_exists("__ANDROID__" "" EZ_TARGET_ANDROID)
check_symbol_exists("_GNU_SOURCE" "" HAVE_GNU_SOURCE)

macro(check_symbol_withlibs symbol files libs result)
	set(_CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES}")
	set(CMAKE_REQUIRED_LIBRARIES "${libs}")
	check_symbol_exists("${symbol}" "${files}" ${result})
	set(CMAKE_REQUIRED_LIBRARIES "${_CMAKE_REQUIRED_LIBRARIES}")
endmacro()

add_definitions(-D__STDC_FORMAT_MACROS)
if(NOT HAVE_GNU_SOURCE)
	add_definitions(-D_GNU_SOURCE)
endif()

if(EZ_TARGET_LINUX OR EZ_TARGET_FREEBSD OR EZ_TARGET_DARWIN)
	set(EZ_TARGET_POSIX TRUE)
endif()

add_compile_options(-Wall)

if(EZ_TARGET_POSIX)
	add_compile_options(-fPIC)
endif()

include(CheckCCompilerFlag)
check_c_compiler_flag("-std=gnu99" HAVE_STDGNU)
# for gcc 3.x
if(HAVE_STDGNU)
	string(APPEND CMAKE_C_FLAGS " -std=gnu99")
endif()


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
		libSystem.B.dylib
	)
	list(APPEND EXTRA_SEARCH_PATHS "/usr/lib/system")
elseif(EZ_TARGET_WINDOWS)
	list(APPEND C_LIBRARY_NAMES
		kernel32
	)
	if(NOT CMAKE_CROSSCOMPILING)
		list(APPEND EXTRA_SEARCH_PATHS "$ENV{SystemRoot}\\System32")
	endif()
endif()

find_library(C_LIBRARY
	NAMES ${C_LIBRARY_NAMES}
	PATHS ${EXTRA_SEARCH_PATHS}
	REQUIRED
)
get_filename_component(C_LIBRARY_NAME "${C_LIBRARY}" NAME)
if(EZ_TARGET_DARWIN)
	if(C_LIBRARY_NAME STREQUAL "libSystem.B.dylib")
		set(REQUIRES_LIBPTHREAD "")
	endif()
endif()

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
		kernel32
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


function(add_ezinject_library target)
	cmake_parse_arguments(LIB "USE_LH;NO_INSTALL" "" "SOURCES" ${ARGN})

	set(sources "${LIB_SOURCES}")

	add_library(${target} SHARED ${sources})

	if(NOT REQUIRES_LIBPTHREAD STREQUAL "")
		target_link_libraries(${target} pthread)
	endif()

	if(NOT DEFINED EZINJECT_CRT_DIR)
		# in-tree build, we can use the objects list
		target_sources(${target} PRIVATE
			$<TARGET_OBJECTS:ezinject_crt>)
	else()
		# out-of-tree build, we use the installed object files
		# (we can't use a static library, since we want all symbols to be exported)
		file(
			GLOB ezinject_crt_objects
			LIST_DIRECTORIES FALSE
			"${EZINJECT_CRT_DIR}/*${CMAKE_C_OUTPUT_EXTENSION}"
		)
		target_sources(${target} PRIVATE ${ezinject_crt_objects})
	endif()

	target_include_directories(${target} PRIVATE ${EZINJECT_INCLUDE_DIRS})

	if(LIB_USE_LH)
		target_compile_definitions(${target} PRIVATE USE_LH)

		# force a dependency on the hook library
		# even if user code doesn't use it
		if(USING_GNU_LD)
			target_link_options(${target} PRIVATE
				-Wl,--whole-archive
					$<TARGET_FILE:lh_ifhook>
				-Wl,--no-whole-archive
			)
		endif()

		target_link_libraries(${target}
			lh_ifcpu
			lh_ifhook
		)
	endif()

	if(NOT LIB_NO_INSTALL)
		install(
			TARGETS ${target}
			LIBRARY DESTINATION bin
		)
	endif()
endfunction()

