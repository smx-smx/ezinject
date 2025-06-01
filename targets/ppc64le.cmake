set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR powerpc64le)

set(CMAKE_C_COMPILER "powerpc64le-linux-gnu-gcc-12")
set(CMAKE_CXX_COMPILER "powerpc64le-linux-gnu-g++-12")
set(CMAKE_AR "powerpc64le-linux-gnu-ar")
set(CMAKE_RANLIB "powerpc64le-linux-gnu-ranlib")

set(CMAKE_SYSROOT  "/")
list(APPEND CMAKE_PREFIX_PATH /usr/powerpc64le-linux-gnu)

set(CMAKE_STRIP "powerpc64le-linux-gnu-strip")
set(CMAKE_SIZE "powerpc64le-linux-gnu-size")
set(CMAKE_OBJCOPY "powerpc64le-linux-gnu-objcopy")
set(CMAKE_READELF "powerpc64le-linux-gnu-readelf")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
