set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(CMAKE_C_COMPILER "arm-linux-gcc")
set(CMAKE_CXX_COMPILER "arm-linux-g++")
set(CMAKE_AR "arm-linux-ar")
set(CMAKE_RANLIB "arm-linux-ranlib")

string(APPEND CMAKE_C_FLAGS " -mcpu=arm920t")

set(CMAKE_FIND_ROOT_PATH "/opt/ttgo/gcc-3.3.4_glibc-2.3.2/arm-linux/sys-root")

set(CMAKE_STRIP "arm-linux-strip")
set(CMAKE_SIZE "arm-linux-size")
set(CMAKE_OBJCOPY "arm-linux-objcopy")
set(CMAKE_READELF "arm-linux-readelf")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
