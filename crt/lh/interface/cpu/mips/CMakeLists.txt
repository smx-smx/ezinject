add_library(libcpu_mips cpu_mips.c)
set_target_properties(libcpu_mips PROPERTIES POSITION_INDEPENDENT_CODE ON)
install(
	TARGETS libcpu_mips
	EXPORT ${ezinject_target_export}
)