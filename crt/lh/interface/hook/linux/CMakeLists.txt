add_library(lh_hook_linux lh_hook.c)
target_link_libraries(lh_hook_linux
	dl
	lh_ifcpu
	${CAPSTONE_LIBRARIES}
)
