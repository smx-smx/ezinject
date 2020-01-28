set(sources common_intel.c)
if( CMAKE_SIZEOF_VOID_P EQUAL 8 )
	list(APPEND sources cpu_x86_64)
else()
	list(APPEND sources cpu_i386.c)
endif()

add_library(libcpu_intel
	${sources}
)
target_link_libraries(libcpu_intel ${CAPSTONE_LIBRARIES} util)
set_target_properties(libcpu_intel PROPERTIES POSITION_INDEPENDENT_CODE ON)