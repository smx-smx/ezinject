cmake_minimum_required(VERSION 3.0)
project(ezpatch C)

include_directories(
	${CMAKE_SOURCE_DIR}
	${CMAKE_BINARY_DIR}
)

if( NOT CMAKE_BUILD_TYPE )
	set(CMAKE_BUILD_TYPE Debug)
endif()

IF(CMAKE_BUILD_TYPE MATCHES Debug)
	set(DEBUG_ENABLE ON)
else()
	set(DEBUG_ENABLE OFF)
endif()

configure_file(
	config.h.in
	${CMAKE_BINARY_DIR}/config.h
)

add_library(common
	util.c
	elfparse.c
)

add_executable(target target.c)

add_executable(ezpatch
	elfparse.c
	ezpatch.c
)
target_link_libraries(ezpatch common)