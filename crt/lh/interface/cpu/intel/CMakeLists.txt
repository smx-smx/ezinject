set(sources common_intel.c)
if(EZ_ARCH_AMD64)
	list(APPEND sources cpu_x86_64.c)
elseif(EZ_ARCH_I386)
	list(APPEND sources cpu_i386.c)
else()
	message(FATAL_ERROR "Unknown Architecture")
endif()

add_library(libcpu_intel
	${sources}
)
install(
	TARGETS libcpu_intel
	EXPORT ${ezinject_target_export}
)