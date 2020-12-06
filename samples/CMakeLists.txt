add_subdirectory(dummy)

option(BUILD_MONO "enable mono module" ON)

add_subdirectory(pyloader)
add_subdirectory(dotnetcore)
if(BUILD_MONO)
	add_subdirectory(mono)
endif()

include(CheckSymbolExists) 
check_symbol_exists("__NR_memfd_create" "asm/unistd.h" HAVE_NR_MEMFD_CREATE)
if(HAVE_NR_MEMFD_CREATE)
	add_subdirectory(memloader)
endif()

