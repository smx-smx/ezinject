add_library(os_darwin inject.c libc_darwin.c remote.c util.c)
target_link_libraries(${EZINJECT_TARGET} os_darwin)