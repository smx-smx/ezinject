add_library(os_android libc_bionic.c)
target_link_libraries(${EZINJECT_TARGET} os_android)