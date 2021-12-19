add_ezinject_library(netapi
	#USE_LOG
	SOURCES netapi.c
)
target_link_libraries(netapi dl)
if(EZ_TARGET_POSIX AND NOT EZ_TARGET_ANDROID)
	target_link_libraries(netapi pthread)
endif()
