# TODO: confirm minimum requirement
cmake_minimum_required(VERSION 3.10)

set(HAVE_CMAKE314 TRUE)
if(${CMAKE_VERSION} VERSION_LESS "3.14") 
	# 3.14 requirement: https://cmake.org/cmake/help/latest/policy/CMP0083.html
    message(WARNING "CMake older than 3.14 detected. You might experience problems with Android builds")
	set(HAVE_CMAKE314 FALSE)
endif()
project(ezpatch C ASM)
enable_language(CXX OPTIONAL)
enable_testing()

if(HAVE_CMAKE314)
	cmake_policy(VERSION 3.14)
	include(CheckPIESupported)
	check_pie_supported()
endif()

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake-modules/")

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

include(CheckSymbolExists)
check_symbol_exists("PSR_T_BIT" "asm/ptrace.h" HAVE_PSR_T_BIT)
check_symbol_exists("strsignal" "string.h" HAVE_STRSIGNAL)
check_symbol_exists("RTLD_NOLOAD" "dlfcn.h" HAVE_RTLD_NOLOAD)
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

if(NOT HAVE_GNU_SOURCE)
	add_definitions(-D_GNU_SOURCE)
endif()

if(EZ_TARGET_LINUX OR EZ_TARGET_FREEBSD OR EZ_TARGET_DARWIN)
	set(EZ_TARGET_POSIX TRUE)
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
	-DLH_JUMP_ABS
)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)


set(_common_flags " -Wall")
if(EZ_TARGET_POSIX)
	string(APPEND _common_flags " -fPIC")
endif()
string(APPEND CMAKE_C_FLAGS ${_common_flags})
string(APPEND CMAKE_CXX_FLAGS ${_common_flags})

include(CheckCCompilerFlag)
check_c_compiler_flag("-Wextra" HAVE_WEXTRA)
check_c_compiler_flag("-Werror=implicit-function-declaration" HAVE_WERROR_IMPLICIT_FN)
check_c_compiler_flag("-std=gnu99" HAVE_STDGNU)

if(HAVE_WEXTRA)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wextra")
endif()
if(HAVE_WERROR_IMPLICIT_FN)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror=implicit-function-declaration")
endif()
# for gcc 3.x
if(HAVE_STDGNU)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")
endif()

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
elseif(EZ_LIBC STREQUAL "glibc-old")
	set(HAVE_LIBC_DL_OPEN TRUE)
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
		set(CMAKE_POSITION_INDEPENDENT_CODE ON)
	elseif(EZ_LIBC_VARIANT STREQUAL "android-10")
		set(CMAKE_POSITION_INDEPENDENT_CODE ON)
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
	AND NOT HAVE_LIBDL_IN_LIBC
	AND NOT EZ_TARGET_DARWIN
	AND NOT EZ_TARGET_LINUX
	AND NOT EZ_TARGET_FREEBSD
)
	message(FATAL_ERROR "Unsupported system")
endif()

if(EZ_ARCH_I386 OR EZ_ARCH_AMD64 OR (EZ_ARCH_ARM AND USE_ARM_THUMB))
	# for ARM, this is true only on Thumb
	set(HAVE_CPU_VLE ON)
endif()

if(USE_CAPSTONE OR (HAVE_CPU_VLE AND NOT USE_FRIDA_GUM))
	set(USE_CAPSTONE ON)
	if(NOT CAPSTONE_PREFIX)
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

configure_file(
	config.h.in
	${CMAKE_BINARY_DIR}/config.h
)

function(add_ezinject_library target)
	cmake_parse_arguments(LIB "USE_LH;USE_LOG" "" "SOURCES" ${ARGN})

	set(sources "${LIB_SOURCES}")

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
					$<TARGET_FILE:lh_hook>
				-Wl,--no-whole-archive
			)
		endif()

		target_link_libraries(${target}
			lh_ifcpu
			lh_hook
		)
	endif()
endfunction()

set(_common_flags "")

if(EZ_TARGET_DARWIN)
	string(APPEND _common_flags " -Wl,-undefined,error")
else()
	string(APPEND _common_flags " -Wl,--no-undefined")
endif()

string(APPEND CMAKE_SHARED_LINKER_FLAGS ${_common_flags})
string(APPEND CMAKE_EXE_LINKER_FLAGS ${_common_flags})


set(lib_sources 
	ezinject_util.c
)
set(target_sources "")
if(EZ_TARGET_POSIX)
	list(APPEND lib_sources
		os/posix/remote.c
	)
	list(APPEND target_sources
		os/posix/inject.c
	)
	if(EZ_TARGET_LINUX)
		list(APPEND lib_sources
			os/linux/remote.c
			os/linux/util.c
		)
		list(APPEND target_sources
			os/linux/inject.c
		)

		# bionic
		if(EZ_TARGET_ANDROID)
			list(APPEND lib_sources
				os/android/libc_bionic.c
				elfparse.c
			)
		# glibc
		elseif(HAVE_LIBC_DLOPEN_MODE OR HAVE_LIBC_DL_OPEN)
			list(APPEND lib_sources
				os/linux/libc_glibc.c
			)
		# uClibc
		elseif(HAVE_DL_LOAD_SHARED_LIBRARY)
			list(APPEND lib_sources
				os/linux/libc_uclibc.c
			)
		endif()
	elseif(EZ_TARGET_FREEBSD)
		list(APPEND lib_sources
			os/freebsd/remote.c
			os/freebsd/util.c
			os/freebsd/libc_freebsd.c
		)
		list(APPEND target_sources
			os/freebsd/inject.c
		)
	elseif(EZ_TARGET_DARWIN)
		list(APPEND lib_sources
			os/darwin/remote.c
			os/darwin/util.c
			os/darwin/libc_darwin.c
		)
		list(APPEND target_sources
			os/darwin/inject.c
		)
	endif()
elseif(EZ_TARGET_WINDOWS)
	list(APPEND lib_sources
		os/windows/remote.c
		os/windows/util.c
		os/windows/libc_windows.c
	)
	list(APPEND target_sources
		os/windows/inject.c
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
	target_link_libraries(ezpatch ${DL_LIBRARY_NAME})
endif()

macro(ezinject_lib target_name mode)
	add_library(${target_name} ${mode} ${lib_sources})
	set_target_properties(${target_name} PROPERTIES OUTPUT_NAME ezinject)
	target_link_libraries(${target_name} ${DL_LIBRARY_NAME})

	if(EZ_TARGET_FREEBSD)
		target_link_libraries(${target_name} procstat)
	endif()
endmacro(ezinject_lib)

ezinject_lib(libezinject_static STATIC)
ezinject_lib(libezinject_shared SHARED)
target_compile_definitions(libezinject_shared PUBLIC -DEZ_SHARED)

set(ezinject_sources
	ezinject.c
	ezinject_injcode.c
	${target_sources}
)

add_executable(ezinject ${ezinject_sources})
target_link_libraries(ezinject libezinject_static)

if(ENABLE_STATIC)
	target_link_options(ezinject PUBLIC -static)
endif()

check_c_compiler_flag("-ffunction-sections" HAVE_CFLAG_FFUNCTION_SECTIONS)
check_c_compiler_flag("-fdata-sections" HAVE_CFLAG_FDATA_SECTIONS)
if(HAVE_CFLAG_FFUNCTION_SECTIONS)
	string(APPEND CMAKE_C_FLAGS " -ffunction-sections")
endif()
if(HAVE_CFLAG_FDATA_SECTIONS)
	string(APPEND CMAKE_C_FLAGS " -fdata-sections")
endif()

check_c_compiler_flag("-mno-stack-arg-probe" HAVE_CFLAG_STACK_ARG_PROBE)
check_c_compiler_flag("-fno-jump-tables" HAVE_CFLAG_NO_JUMP_TABLES)
check_c_compiler_flag("-fno-stack-protector" HAVE_CFLAG_NO_STACK_PROTECTOR)

set(injcode_cflags "-Os -fno-stack-check -fno-pic -nostdlib -fomit-frame-pointer -ffreestanding")
if(HAVE_CFLAG_NO_JUMP_TABLES)
	set(injcode_cflags "${injcode_cflags} -fno-jump-tables")
endif()
if(HAVE_CFLAG_NO_STACK_PROTECTOR)
	set(injcode_cflags "${injcode_cflags} -fno-stack-protector")
endif()
if(HAVE_CFLAG_STACK_ARG_PROBE)
	set(injcode_cflags "${injcode_cflags} -mno-stack-arg-probe")
endif()

# -fno-stack-protector: remove stack cookie checks
# -fno-pic: remove calls to __x86_get_pc_thunk_ax
# -nostdlib: this code doesn't use any library
# -fomit-frame-pointer: don't save stack frames
# -ffreestanding: don't assume libc functions exist
# -fno-stack-check,-mno-stack-arg-probe: don't emit ___chkstk_ms calls
set_source_files_properties(ezinject_injcode.c PROPERTIES COMPILE_FLAGS "${injcode_cflags}")
if(EZ_TARGET_POSIX)
	target_link_libraries(ezinject dl)
endif()

add_subdirectory(crt)

if(USE_FRIDA_GUM)
	find_library(FRIDA_CAPSTONE_LIBRARY
		PATHS ${FRIDA_PREFIX}
		PATH_SUFFIXES lib
		NAMES
			libcapstone.a
		REQUIRED
		NO_CMAKE_FIND_ROOT_PATH
		NO_DEFAULT_PATH
	)

	find_library(GLIB_LIBRARY
		PATHS ${FRIDA_PREFIX}
		PATH_SUFFIXES lib
		NAMES
			libglib-2.0.a
		REQUIRED
		NO_CMAKE_FIND_ROOT_PATH
		NO_DEFAULT_PATH
	)

	if(EZ_ARCH_AMD64 OR EZ_ARCH_I386)
		find_library(FADEC_LIBRARY
			PATHS ${FRIDA_PREFIX}
			PATH_SUFFIXES lib
			NAMES
				libfadec.a
			REQUIRED
			NO_CMAKE_FIND_ROOT_PATH
			NO_DEFAULT_PATH
		)
	endif()

	## non-diet mode libraries
	find_library(LIBELF_LIBRARY
		PATHS ${FRIDA_PREFIX}
		PATH_SUFFIXES lib
		NAMES
			libelf.a
		REQUIRED
		NO_CMAKE_FIND_ROOT_PATH
		NO_DEFAULT_PATH
	)

	find_library(GOBJECT_LIBRARY
		PATHS ${FRIDA_PREFIX}
		PATH_SUFFIXES lib
		NAMES
			libgobject-2.0.a
		REQUIRED
		NO_CMAKE_FIND_ROOT_PATH
		NO_DEFAULT_PATH
	)
	find_library(FFI_LIBRARY
		PATHS ${FRIDA_PREFIX}
		PATH_SUFFIXES lib
		NAMES
			libffi.a
		REQUIRED
		NO_CMAKE_FIND_ROOT_PATH
		NO_DEFAULT_PATH
	)
	##

	find_library(FRIDA_GUM_LIBRARY
		PATHS ${FRIDA_PREFIX}
		PATH_SUFFIXES lib
		NAMES
			libfrida-gum-1.0.a
		REQUIRED
		NO_CMAKE_FIND_ROOT_PATH
		NO_DEFAULT_PATH
	)

	add_link_options(-Wl,--gc-sections)

	add_library(frida-gum-static STATIC IMPORTED)
	set_target_properties(frida-gum-static PROPERTIES
		IMPORTED_LOCATION ${FRIDA_GUM_LIBRARY}
	)

	target_link_libraries(frida-gum-static INTERFACE
		${GOBJECT_LIBRARY} 
		${GLIB_LIBRARY}
		${FRIDA_CAPSTONE_LIBRARY}
		${FFI_LIBRARY}
		${LIBELF_LIBRARY}
	)
	if(EZ_ARCH_AMD64 OR EZ_ARCH_I386)
		target_link_libraries(frida-gum-static INTERFACE ${FADEC_LIBRARY})
	endif()
endif()

add_subdirectory(samples)

include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-std=c++11" COMPILER_SUPPORTS_CXX11)
if(COMPILER_SUPPORTS_CXX11)
	add_subdirectory(test)
endif()