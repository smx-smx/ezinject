add_ezinject_library(webapi
	#USE_LOG
	SOURCES webapi.c
)
target_link_libraries(webapi dl)
if(EZ_TARGET_POSIX AND NOT EZ_TARGET_ANDROID)
	target_link_libraries(webapi pthread)
endif()