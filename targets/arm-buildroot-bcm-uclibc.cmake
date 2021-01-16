set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(CMAKE_C_COMPILER "arm-buildroot-linux-uclibcgnueabi-gcc")
set(CMAKE_CXX_COMPILER "arm-buildroot-linux-uclibcgnueabi-g++")
set(CMAKE_AR "arm-buildroot-linux-uclibcgnueabi-ar")
set(CMAKE_RANLIB "arm-buildroot-linux-uclibcgnueabi-ranlib")

set(CMAKE_SYSROOT "/mnt/ExtData/cross/buildroot/output/staging")

set(CMAKE_STRIP "arm-buildroot-linux-uclibcgnueabi-strip")
set(CMAKE_SIZE "arm-buildroot-linux-uclibcgnueabi-size")
set(CMAKE_OBJCOPY "arm-buildroot-linux-uclibcgnueabi-objcopy")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)