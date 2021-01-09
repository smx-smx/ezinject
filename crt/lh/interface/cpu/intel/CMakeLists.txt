set(sources common_intel.c)
if(EZ_ARCH_AMD64)
	list(APPEND sources cpu_x86_64)
elseif(EZ_ARCH_I386)
	list(APPEND sources cpu_i386.c)
else()
	message(FATAL_ERROR "Unknown Architecture")
endif()

add_library(libcpu_intel
	${sources}
)
target_link_libraries(libcpu_intel ${CAPSTONE_LIBRARIES} util)
set_target_properties(libcpu_intel PROPERTIES POSITION_INDEPENDENT_CODE ON)