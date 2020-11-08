add_subdirectory(dummy)

option(BUILD_MONO "enable mono module" ON)

add_subdirectory(pyloader)
add_subdirectory(dotnetcore)
if(BUILD_MONO)
	add_subdirectory(mono)
endif()
add_subdirectory(memloader)
