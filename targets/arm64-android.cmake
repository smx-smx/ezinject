set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm64)

set(ANDROID TRUE)

set(CMAKE_C_COMPILER "aarch64-linux-android-gcc")
set(CMAKE_CXX_COMPILER "aarch64-linux-android-g++")

set(CMAKE_AR "aarch64-linux-android-ar")
set(CMAKE_RANLIB "aarch64-linux-android-ranlib")

set(CMAKE_STRIP "aarch64-linux-android-strip")
set(CMAKE_SIZE "aarch64-linux-android-size")
set(CMAKE_OBJCOPY "aarch64-linux-android-objcopy")

set(CMAKE_SYSROOT "/opt/android-ndk-r14b-android-21-arm64/sysroot")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# cache flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}" CACHE STRING "c flags")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}" CACHE STRING "c++ flags")
