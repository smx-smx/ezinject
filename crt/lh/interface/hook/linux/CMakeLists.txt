add_library(lh_hook_linux lh_hook.c)
target_link_libraries(lh_hook_linux
	dl
	lh_ifcpu
	lh_elf
	${CAPSTONE_LIBRARIES}
)
set_target_properties(lh_hook_linux PROPERTIES POSITION_INDEPENDENT_CODE ON)
