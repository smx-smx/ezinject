add_subdirectory(dummy)

if(CMAKE_CXX_COMPILER_WORKS)
	add_subdirectory(cpp)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(MONO mono-2)

add_subdirectory(pyloader)
add_subdirectory(dotnetcore)
if(MONO_FOUND)
	add_subdirectory(mono)
endif()

include(CheckSymbolExists) 
check_symbol_exists("__NR_memfd_create" "asm/unistd.h" HAVE_NR_MEMFD_CREATE)
if(HAVE_NR_MEMFD_CREATE)
	add_subdirectory(memloader)
endif()

