set(LH_TOP ${CMAKE_CURRENT_SOURCE_DIR})
include_directories(
    ${CMAKE_BINARY_DIR} # config.h
    ${CMAKE_SOURCE_DIR} # log.h
    ${LH_TOP}
)
add_subdirectory(interface)
