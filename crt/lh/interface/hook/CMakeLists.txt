add_library(lh_hook lh_hook.c)
target_link_libraries(lh_hook
	dl
	lh_ifcpu
	${CAPSTONE_LIBRARIES}
)
