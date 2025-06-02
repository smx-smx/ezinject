set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR riscv64)

set(CMAKE_C_COMPILER "riscv64-linux-gnu-gcc-12")
set(CMAKE_CXX_COMPILER "riscv64-linux-gnu-g++-12")
set(CMAKE_AR "riscv64-linux-gnu-ar")
set(CMAKE_RANLIB "riscv64-linux-gnu-ranlib")

set(CMAKE_SYSROOT  "/")
list(APPEND CMAKE_PREFIX_PATH /usr/riscv64-linux-gnu)

set(CMAKE_STRIP "riscv64-linux-gnu-strip")
set(CMAKE_SIZE "riscv64-linux-gnu-size")
set(CMAKE_OBJCOPY "riscv64-linux-gnu-objcopy")
set(CMAKE_READELF "riscv64-linux-gnu-readelf")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
