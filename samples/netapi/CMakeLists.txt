add_ezinject_library(netapi
	#USE_LOG
	SOURCES netapi.c
)
if(EZ_TARGET_POSIX)
	target_link_libraries(netapi dl)
	if(NOT EZ_TARGET_ANDROID)
		target_link_libraries(netapi pthread)
	endif()
elseif(EZ_TARGET_WINDOWS)
	target_link_libraries(netapi ws2_32 pthread)
endif()

