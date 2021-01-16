set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR mips)

set(CMAKE_C_COMPILER "mips-linux-gcc")
set(CMAKE_CXX_COMPILER "mips-linux-g++")
set(CMAKE_AR "mips-linux-ar")
set(CMAKE_RANLIB "mips-linux-ranlib")

set(CMAKE_SYSROOT  "/opt/trendchip/mips-linux-uclibc")
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)

set(CMAKE_STRIP "mips-linux-strip")
set(CMAKE_SIZE "mips-linux-size")
set(CMAKE_OBJCOPY "mips-linux-objcopy")
set(CMAKE_READELF "mips-linux-readelf")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
