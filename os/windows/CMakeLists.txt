add_library(os_windows
	inject.c
	libc_windows.c
	remote.c
	util.c util.h
)

add_subdirectory(InjLib)
target_link_libraries(${EZINJECT_TARGET} os_windows windows_injlib)

install(
	FILES util.h
	DESTINATION include/ezinject/os/windows
)