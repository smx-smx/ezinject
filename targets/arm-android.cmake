set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR armv7-a)

set(ANDROID TRUE)

set(CMAKE_C_COMPILER "arm-linux-androideabi-gcc")
set(CMAKE_CXX_COMPILER "arm-linux-androideabi-g++")

set(CMAKE_AR "arm-linux-androideabi-ar")
set(CMAKE_RANLIB "arm-linux-androideabi-ranlib")

set(CMAKE_STRIP "arm-linux-androideabi-strip")
set(CMAKE_SIZE "arm-linux-androideabi-size")
set(CMAKE_OBJCOPY "arm-linux-androideabi-objcopy")

set(CMAKE_SYSROOT "/opt/android-ndk-r14b-android-9/sysroot")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# cache flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}" CACHE STRING "c flags")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}" CACHE STRING "c++ flags")
