add_library(os_freebsd inject.c libc_freebsd.c remote.c util.c)
target_link_libraries(${EZINJECT_TARGET} os_freebsd)