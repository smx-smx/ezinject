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
