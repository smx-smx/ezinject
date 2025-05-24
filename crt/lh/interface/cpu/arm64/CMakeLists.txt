add_library(libcpu_arm64 cpu_arm64.c)
install(
	TARGETS libcpu_arm64
	EXPORT ${ezinject_target_export}
)