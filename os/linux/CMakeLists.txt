add_library(os_linux_util util.c)
add_library(os_linux
	common.c
	inject.c
	remote.c
)

if(HAVE_LIBC_DLOPEN_MODE OR HAVE_LIBC_DL_OPEN)
	target_sources(os_linux PRIVATE libc_glibc.c)
elseif(HAVE_DL_LOAD_SHARED_LIBRARY)
	target_sources(os_linux PRIVATE libc_uclibc.c)
else()
	target_sources(os_linux PRIVATE libc_generic.c)
endif()

target_link_libraries(${EZINJECT_TARGET}
	os_linux
	os_linux_util
)