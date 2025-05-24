if(OUT_OF_TREE)
	project(ezinject_samples)
	cmake_minimum_required(VERSION 3.14)

	set(CMAKE_C_STANDARD 99)
	set(CMAKE_CXX_STANDARD 11)
	
	if(NOT DEFINED EZINJECT_PREFIX)
		message(FATAL_ERROR "set EZINJECT_PREFIX to the ezinject installation prefix (e.g. /usr/local)")
	endif()

	#list(INSERT CMAKE_PREFIX_PATH 0 "${EZINJECT_PREFIX}")
	list(INSERT CMAKE_FIND_ROOT_PATH 0 "${EZINJECT_PREFIX}")
	find_package(ezinject REQUIRED)
else()
	list(INSERT CMAKE_MODULE_PATH 0 "${CMAKE_SOURCE_DIR}/cmake")
	include(ezinject)
endif()

add_subdirectory(dummy)
add_subdirectory(pyloader)

if(CMAKE_CXX_COMPILER_WORKS AND ENABLE_CPP_SAMPLES)
	add_subdirectory(cpp)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(MONO mono-2)

if(NOT EZ_TARGET_ANDROID AND NOT EZ_TARGET_WINDOWS)
	add_subdirectory(dotnetcore)
	if(MONO_FOUND AND ENABLE_MONO_SAMPLE)
		add_subdirectory(mono)
	endif()
endif()

if(EZ_TARGET_LINUX)
	include(CheckSymbolExists)
	check_symbol_exists("__NR_memfd_create" "asm/unistd.h" HAVE_NR_MEMFD_CREATE)
	if(HAVE_NR_MEMFD_CREATE)
		add_subdirectory(memloader)
	endif()
endif()

if(ENABLE_PHP_SAMPLE)
	add_subdirectory(php)
endif()

add_subdirectory(netapi)
