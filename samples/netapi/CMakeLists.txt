add_ezinject_library(netapi
	#USE_LOG
	SOURCES netapi.c
)
target_link_libraries(netapi dl)
if(EZ_TARGET_POSIX AND NOT EZ_TARGET_ANDROID)
	target_link_libraries(netapi pthread)
elseif(EZ_TARGET_WINDOWS)
	target_link_libraries(netapi ws2_32)
endif()

