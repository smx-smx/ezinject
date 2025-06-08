set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR hppa)

set(CMAKE_C_COMPILER "hppa-linux-gnu-gcc-12")
set(CMAKE_CXX_COMPILER "hppa-linux-gnu-g++-12")
set(CMAKE_AR "hppa-linux-gnu-ar")
set(CMAKE_RANLIB "hppa-linux-gnu-ranlib")

set(CMAKE_SYSROOT  "/")
list(APPEND CMAKE_PREFIX_PATH /usr/hppa-linux-gnu)

set(CMAKE_STRIP "hppa-linux-gnu-strip")
set(CMAKE_SIZE "hppa-linux-gnu-size")
set(CMAKE_OBJCOPY "hppa-linux-gnu-objcopy")
set(CMAKE_READELF "hppa-linux-gnu-readelf")

string(APPEND CMAKE_C_FLAGS_INIT " -march=1.1")
string(APPEND CMAKE_CXX_FLAGS_INIT " -march=1.1")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
