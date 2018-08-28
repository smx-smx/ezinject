set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR mips)

set(CMAKE_C_COMPILER "mips-linux-uclibc-gcc")
set(CMAKE_CXX_COMPILER "mips-linux-uclibc-g++")
set(CMAKE_AR "mips-linux-uclibc-ar" CACHE FILEPATH "")
set(CMAKE_RANLIB "mips-linux-uclibc-ranlib" CACHE FILEPATH "")

set(CMAKE_BUILD_RPATH "/opt/toolchains/crosstools-arm-gcc-4.6-linux-3.4-uclibc-0.9.32-binutils-2.21-NPTL/lib")

set(CMAKE_STRIP "mips-linux-uclibc-strip" CACHE FILEPATH "")
set(CMAKE_SIZE "mips-linux-uclibc-size" CACHE FILEPATH "")
set(CMAKE_OBJCOPY "mips-linux-uclibc-objcopy" CACHE FILEPATH "")
