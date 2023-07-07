set(CMAKE_SYSTEM_NAME FreeBSD)
set(CMAKE_SYSTEM_PROCESSOR "i686")

set(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_COMPILER g++)

set(_common_cflags "-m32 -B/usr/lib32 -B/usr/local/lib32/gcc9")
set(_common_ldflags "-rpath-link /usr/lib32")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${_common_cflags}" CACHE STRING "c++ flags")
set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} ${_common_cflags}" CACHE STRING "c flags")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${_common_ldflags}" CACHE STRING "linker flags")