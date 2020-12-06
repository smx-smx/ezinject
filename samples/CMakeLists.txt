add_subdirectory(dummy)

option(BUILD_MONO "enable mono module" ON)

add_subdirectory(pyloader)
add_subdirectory(dotnetcore)
if(BUILD_MONO)
	add_subdirectory(mono)
endif()

include(CheckIncludeFiles) 
check_include_files("linux/memfd.h" HAVE_LINUX_MEMFD)
if(HAVE_LINUX_MEMFD)
	add_subdirectory(memloader)
endif()

