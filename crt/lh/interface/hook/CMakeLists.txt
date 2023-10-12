add_library(lh_hook lh_hook.c)
target_link_libraries(lh_hook
	lh_ifcpu
	${CAPSTONE_LIBRARIES}
)
