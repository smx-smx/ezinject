add_library(lh_ifhook lh_hook.c)
target_link_libraries(lh_ifhook
	lh_ifcpu
	${CAPSTONE_LIBRARIES}
)
install(
	TARGETS lh_ifhook
	EXPORT ${ezinject_target_export}
)