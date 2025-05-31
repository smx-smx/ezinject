# TODO: confirm minimum requirement
cmake_minimum_required(VERSION 3.14)

set(HAVE_CMAKE314 TRUE)
if(${CMAKE_VERSION} VERSION_LESS "3.14")
	# 3.14 requirement: https://cmake.org/cmake/help/latest/policy/CMP0083.html
    message(WARNING "CMake older than 3.14 detected. You might experience problems with Android builds")
	set(HAVE_CMAKE314 FALSE)
endif()
project(ezinject C ASM)
enable_language(CXX OPTIONAL)
enable_testing()

if(HAVE_CMAKE314)
	cmake_policy(VERSION 3.14)
	include(CheckPIESupported)
	check_pie_supported()
endif()

set(ezinject_target_export ezinject-targets)
install(
	EXPORT ${ezinject_target_export}
	FILE ezinject-targets.cmake
	DESTINATION lib/cmake/ezinject
)
include(CMakePackageConfigHelpers)
set(INCLUDE_INSTALL_DIR include/ezinject)
set(CRT_INSTALL_DIR lib/ezinject/crt)
configure_package_config_file(cmake/config.cmake.in
	"${CMAKE_BINARY_DIR}/ezinject-config.cmake"
	INSTALL_DESTINATION "lib/cmake/ezinject"
	PATH_VARS
		INCLUDE_INSTALL_DIR
		CRT_INSTALL_DIR
)
install(
	FILES
		${CMAKE_BINARY_DIR}/ezinject-config.cmake
		cmake/ezinject.cmake
	DESTINATION lib/cmake/ezinject
)


set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake-modules/")
include(cmake/ezinject.cmake)

add_definitions(-DLH_JUMP_ABS)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)

add_compile_options(-Wall)
include(CheckCCompilerFlag)
check_c_compiler_flag("-Wextra" HAVE_WEXTRA)
check_c_compiler_flag("-Werror=implicit-function-declaration" HAVE_WERROR_IMPLICIT_FN)
check_c_compiler_flag("-Wno-unused-parameter" HAVE_WNO_UNUSED_PARAMETER)
check_c_compiler_flag("-Wno-cast-function-type" HAVE_WNO_CAST_FUNCTION_TYPE)

if(HAVE_WEXTRA)
	add_compile_options(-Wextra)
endif()
if(HAVE_WERROR_IMPLICIT_FN)
	add_compile_options(
		$<$<COMPILE_LANGUAGE:C>:-Werror=implicit-function-declaration>)
endif()
if(HAVE_WNO_UNUSED_PARAMETER)
	add_compile_options(-Wno-unused-parameter)
endif()
if(HAVE_WNO_CAST_FUNCTION_TYPE)
	add_compile_options(-Wno-cast-function-type)
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



macro(find_uclibc)
	find_library(DYN_LINKER
		NAMES ld-uClibc.so.0
	)
	if(DYN_LINKER)
		get_filename_component(DYN_LINKER_NAME "${DYN_LINKER}" NAME)
	endif()
endmacro()

function(export_var var)
	get_property(libc_props GLOBAL PROPERTY libc_props)
	list(APPEND libc_props "${var}")
	set_property(GLOBAL PROPERTY libc_props "${libc_props}")

	set_property(GLOBAL PROPERTY "${var}" "${${var}}")
endfunction()

function(libc_type_autodetect)
	# handle windows platform early, as it's special
	if(EZ_TARGET_WINDOWS)
		check_library_exists("${C_LIBRARY}" "LdrLoadDll" "" HAVE_LDR_LOAD_DLL)
		check_library_exists("${DL_LIBRARY}" "LoadLibraryA" "" HAVE_LOADLIBRARY)
		# TODO: fix after rebase
		if((NOT HAVE_LDR_LOAD_DLL AND NOT HAVE_LOADLIBRARY) AND FALSE)
			message(FATAL_ERROR "Invalid or unsupported ntdll.dll")
		endif()
		# TODO: fix after rebase
		if(NOT HAVE_LOADLIBRARY AND FALSE)
			message(FATAL_ERROR "Invalid or unsupported kernel32.dll")
		endif()

		export_var(HAVE_LDR_LOAD_DLL)
		export_var(HAVE_LOADLIBRARY)
		return()
	endif()

	# check if we have __libc_dlopen_mode (glibc)
	check_library_exists("${C_LIBRARY}" "__libc_dlopen_mode" "" HAVE_LIBC_DLOPEN_MODE)
	export_var(HAVE_LIBC_DLOPEN_MODE)

	if(HAVE_LIBC_DLOPEN_MODE)
		return()
	endif()

	# check if libc contains dlopen/dlsym (freebsd/glibc >= 2.34)
	check_library_exists("${C_LIBRARY}" "dlopen" "" HAVE_DLOPEN)
	check_library_exists("${C_LIBRARY}" "dlopen" "" HAVE_DLSYM)

	if(HAVE_DLOPEN AND HAVE_DLSYM)
		set(HAVE_LIBDL_IN_LIBC TRUE)
		export_var(HAVE_LIBDL_IN_LIBC)
		return()
	else()
		unset(HAVE_DLOPEN CACHE)
		unset(HAVE_DLSYM CACHE)
	endif()

	# check if we're targeting uClibc
	find_uclibc()
	if(DYN_LINKER)
		export_var(DYN_LINKER_NAME)
		check_library_exists("${DYN_LINKER}" "_dl_load_shared_library" "" HAVE_DL_LOAD_SHARED_LIBRARY)

		if(EZ_ARCH_MIPS)
			# FIXME: how to better check for uClibc version?
			# assuming MIPS uses old uClibc for now (which isn't always true)
			set(UCLIBC_OLD TRUE)
			export_var(UCLIBC_OLD)
		endif()
	endif()
endfunction()

function(linker_type_autodetect)
	if(EZ_TARGET_WINDOWS)
		# Windows always uses kernel32 (win9x) and/or ntdll (NT)
		return()
	endif()

	if(NOT EZ_TARGET_DARWIN)
		check_library_exists("${DL_LIBRARY}" "dlopen" "" HAVE_DLOPEN)
		check_library_exists("${DL_LIBRARY}" "dlsym" "" HAVE_DLSYM)
		if(NOT HAVE_DLOPEN OR NOT HAVE_DLSYM)
			message(FATAL_ERROR "Invalid libdl.so library")
		endif()

		export_var(HAVE_DLOPEN)
		export_var(HAVE_DLSYM)
	endif()

	# set dynamic linker name
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
endfunction()

function(libc_autodetect)
	## check libc type
	libc_type_autodetect()

	## now check for libdl
	linker_type_autodetect()

	get_property(libc_props GLOBAL PROPERTY libc_props)
	foreach(prop ${libc_props})
		get_property(prop_value GLOBAL PROPERTY ${prop})
		set(${prop} "${prop_value}" PARENT_SCOPE)
	endforeach()
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
	if(EZ_LIBC_VARIANT STREQUAL "android-2")
	message(FATAL_ERROR "${DYN_LINKER_NAME}")
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
	set(CAPSTONE_REQUIRED "")
	# if user requested, it's a required dependency
	if(USE_CAPSTONE)
		set(CAPSTONE_REQUIRED REQUIRED)
	endif()
	if(NOT CAPSTONE_PREFIX)
		# try to find capstone
		if(NOT CAPSTONE_INCLUDE_DIRS AND NOT CAPSTONE_LIBRARIES)
			find_package(CAPSTONE ${CAPSTONE_REQUIRED})
		endif()
		if(CAPSTONE_FOUND AND DEFINED CAPSTONE_INCLUDE_DIRS)
			include_directories(${CAPSTONE_INCLUDE_DIRS})
			# found usable capstone
			set(USE_CAPSTONE TRUE)
		endif()
	else()
		# user provided path
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

if(EZ_TARGET_WINDOWS)
	unset(C_LIBRARY_NAME CACHE)
	unset(DL_LIBRARY_NAME CACHE)
	unset(PTHREAD_LIBRARY_NAME CACHE)

	# set runtime dynamic library names
	set(C_LIBRARY_NAME "ntdll.dll")
	set(DL_LIBRARY_NAME "kernel32.dll")
	set(PTHREAD_LIBRARY_NAME ${DL_LIBRARY_NAME})
endif()


set(EZ_ARCH_HEADER "")
if(EZ_TARGET_LINUX)
	if(EZ_ARCH_ARM64)
		set(EZ_ARCH_HEADER arch/ezinject_aarch64.h)
	elseif(EZ_ARCH_ARM)
		set(EZ_ARCH_HEADER arch/ezinject_arm.h)
	elseif(EZ_ARCH_I386)
		set(EZ_ARCH_HEADER arch/ezinject_i386.h)
	elseif(EZ_ARCH_AMD64)
		set(EZ_ARCH_HEADER arch/ezinject_amd64.h)
	elseif(EZ_ARCH_MIPS)
		set(EZ_ARCH_HEADER arch/ezinject_mips.h)
	endif()
elseif(EZ_TARGET_FREEBSD)
	if(EZ_ARCH_AMD64)
		set(EZ_ARCH_HEADER arch/ezinject_freebsd_amd64.h)
	elseif(EZ_ARCH_I386)
		set(EZ_ARCH_HEADER arch/ezinject_freebsd_i386.h)
	endif()
elseif(EZ_TARGET_DARWIN)
	if(EZ_ARCH_AMD64)
		set(EZ_ARCH_HEADER arch/ezinject_darwin_amd64.h)
	endif()
elseif(EZ_TARGET_WINDOWS)
	if(EZ_ARCH_AMD64)
		set(EZ_ARCH_HEADER arch/ezinject_windows_amd64.h)
	elseif(EZ_ARCH_I386)
		set(EZ_ARCH_HEADER arch/ezinject_windows_i386.h)
	endif()
endif()

if(EZ_ARCH_HEADER STREQUAL "")
	message(FATAL_ERROR "Unsupported architecture")
endif()

configure_file(
	config.h.in
	${CMAKE_BINARY_DIR}/config.h
)

add_library(ezinject_crt OBJECT
	crt/crt.c crt/crt.h
	crt/crt_user.c
	crt/crt_injcode.c
	ezinject_util.c ezinject_util.h
	log.c log.h
)
set(ezinject_crt_objects $<TARGET_OBJECTS:ezinject_crt>)
install(FILES ${ezinject_crt_objects}
		DESTINATION lib/ezinject/crt)

set(EZINJECT_INCLUDE_DIRS
	${CMAKE_SOURCE_DIR}
	${CMAKE_BINARY_DIR}
	${CMAKE_SOURCE_DIR}/crt/lh
)
set(ezinject_headers
	dlfcn_compat.h
	ezinject_arch.h
	ezinject_common.h
	ezinject_compat.h
	ezinject_injcode.h
	ezinject_module.h
	ezinject_util.h
	ezinject.h
	log.h
)

target_include_directories(ezinject_crt
	PUBLIC
		$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
		$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}>
		$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/crt/lh>
		$<INSTALL_INTERFACE:include/ezinject>
)
install(
	FILES
		${ezinject_headers}
		${CMAKE_BINARY_DIR}/config.h
	DESTINATION include/ezinject
)

set(all_headers ${ezinject_headers})

if(EZ_TARGET_WINDOWS)
	list(APPEND all_headers
		os/windows/util.h
		os/windows/InjLib/Struct.h)
	install(
		FILES
			os/windows/InjLib/Struct.h
		DESTINATION
			include/ezinject/os/windows/InjLib
	)
	install(
		FILES
			os/windows/util.h
		DESTINATION
			include/ezinject/os/windows
	)
endif()



install(
	FILES ${EZ_ARCH_HEADER}
	DESTINATION include/ezinject/arch
)
install(
	FILES
		crt/lh/interface/if_hook.h
	DESTINATION include/ezinject/interface
)

if(EZ_TARGET_POSIX)
	target_sources(ezinject_crt PRIVATE
		crt/crt_posix.c
	)
elseif(EZ_TARGET_WINDOWS)
	target_sources(ezinject_crt PRIVATE
		crt/crt_windows.c
		os/windows/util.c os/windows/util.h
	)
endif()

set(_common_flags "")

if(EZ_TARGET_DARWIN)
	add_link_options("LINKER:-undefined,error")
else()
	add_link_options("LINKER:--no-undefined")
endif()

string(APPEND CMAKE_SHARED_LINKER_FLAGS ${_common_flags})
string(APPEND CMAKE_EXE_LINKER_FLAGS ${_common_flags})


set(ezinject_sources
	ezinject_util.c
)
if(EZ_TARGET_POSIX)
	list(APPEND ezinject_sources
		os/posix/remote.c
	)
	list(APPEND ezinject_sources
		os/posix/inject.c
	)
	if(EZ_TARGET_LINUX)
		list(APPEND ezinject_sources
			os/linux/common.c os/linux/common.h
			os/linux/remote.c
			os/linux/util.c
		)
		list(APPEND ezinject_sources
			os/linux/inject.c
		)

		# bionic
		if(EZ_TARGET_ANDROID)
			list(APPEND ezinject_sources
				os/android/libc_bionic.c
				elfparse.c elfparse.h
			)
		# glibc
		elseif(HAVE_LIBC_DLOPEN_MODE OR HAVE_LIBC_DL_OPEN)
			list(APPEND ezinject_sources
				os/linux/libc_glibc.c
			)
		# uClibc
		elseif(HAVE_DL_LOAD_SHARED_LIBRARY)
			list(APPEND ezinject_sources
				os/linux/libc_uclibc.c
			)
		# new glibc/generic
		else()
			list(APPEND ezinject_sources
				os/linux/libc_generic.c
			)
		endif()
	elseif(EZ_TARGET_FREEBSD)
		list(APPEND ezinject_sources
			os/freebsd/remote.c
			os/freebsd/util.c
			os/freebsd/libc_freebsd.c
		)
		list(APPEND ezinject_sources
			os/freebsd/inject.c
		)
	elseif(EZ_TARGET_DARWIN)
		list(APPEND ezinject_sources
			os/darwin/remote.c
			os/darwin/util.c
			os/darwin/libc_darwin.c
		)
		list(APPEND ezinject_sources
			os/darwin/inject.c
		)
	endif()
elseif(EZ_TARGET_WINDOWS)
	list(APPEND ezinject_sources
		# InjLib
		os/windows/InjLib/GetProcAddress.c os/windows/InjLib/GetProcAddress.h
		os/windows/InjLib/Inject.c os/windows/InjLib/Inject.h
		os/windows/InjLib/LenDis.c os/windows/InjLib/LenDis.h
		os/windows/InjLib/Remote.c os/windows/InjLib/Remote.h
		#
		os/windows/remote.c
		os/windows/util.c os/windows/util.h
		os/windows/libc_windows.c

		os/windows/InjLib/Struct.h
	)
	list(APPEND ezinject_sources
		os/posix/inject.c
		os/windows/inject.c
	)
endif()

# TODO: cross platform
if(EZ_TARGET_LINUX)
	add_executable(ezpatch
		elfparse.c elfparse.h
		ezpatch.c
		log.c log.h
		ezinject_util.c ezinject_util.h
		os/linux/util.c
	)
	target_link_libraries(ezpatch ${DL_LIBRARY_NAME})
	target_include_directories(ezpatch PRIVATE
		${CMAKE_BINARY_DIR}
		${CMAKE_SOURCE_DIR}
		${CMAKE_SOURCE_DIR}/include
	)
	install(
		TARGETS ezpatch
		EXPORT ${ezinject_target_export}
	)
endif()

add_library(libezinject_static
	log.c
	${ezinject_sources}
)
target_include_directories(libezinject_static PUBLIC
	${CMAKE_SOURCE_DIR}
	${CMAKE_BINARY_DIR})

add_executable(ezinject
	ezinject.c
	ezinject_injcode.c
	${all_headers}
)
target_link_libraries(ezinject libezinject_static)

if(EZ_TARGET_FREEBSD)
	target_link_libraries(ezinject procstat)
endif()

if(ENABLE_STATIC)
	target_link_options(ezinject PRIVATE -static)
endif()
install(
	TARGETS ezinject
	EXPORT ${ezinject_target_export}
)

check_c_compiler_flag("-ffunction-sections" HAVE_CFLAG_FFUNCTION_SECTIONS)
check_c_compiler_flag("-fdata-sections" HAVE_CFLAG_FDATA_SECTIONS)
if(HAVE_CFLAG_FFUNCTION_SECTIONS)
	add_compile_options(-ffunction-sections)
endif()
if(HAVE_CFLAG_FDATA_SECTIONS)
	add_compile_options(-fdata-sections)
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
set_source_files_properties(
	ezinject_injcode.c
	crt/crt_injcode.c
	PROPERTIES COMPILE_FLAGS "${injcode_cflags}")


if(EZ_TARGET_POSIX)
	target_link_libraries(ezinject dl)
endif()

add_subdirectory(crt)

if(USE_FRIDA_GUM)
	find_package(PkgConfig REQUIRED)

	# do we have frida-gum?
	pkg_check_modules(FRIDA_GUM
		IMPORTED_TARGET frida-gum-1.0 GLOBAL
	)

	if(NOT FRIDA_GUM)
		execute_process(
			COMMAND ${CMAKE_COMMAND}
				-G "${CMAKE_GENERATOR}"
				-B "${CMAKE_BINARY_DIR}/external"
				-S "${CMAKE_SOURCE_DIR}/external/frida-gum"
			COMMAND ${CMAKE_COMMAND}
				--build
				${CMAKE_SOURCE_DIR}/external/frida-gum
		)
	endif()

	# check for it again, this time we must have it
	pkg_check_modules(FRIDA_GUM_STATIC
		REQUIRED
		IMPORTED_TARGET frida-gum-1.0 GLOBAL
	)

	include(CMakePrintHelpers)
	cmake_print_properties(TARGETS
		PkgConfig::FRIDA_GUM_STATIC
	PROPERTIES
		INTERFACE_LINK_LIBRARIES
	)

	add_link_options("LINKER:--gc-sections")
endif()

add_subdirectory(samples)

include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-std=c++11" COMPILER_SUPPORTS_CXX11)
if(COMPILER_SUPPORTS_CXX11)
	add_subdirectory(test)
endif()
