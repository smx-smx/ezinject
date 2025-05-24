add_library(libcpu_arm cpu_arm.c)
install(
	TARGETS libcpu_arm
	EXPORT ${ezinject_target_export}
)