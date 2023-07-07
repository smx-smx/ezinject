add_ezinject_library(pyloader
	#USE_LOG
	SOURCES pyloader.c
)
if(EZ_TARGET_POSIX)
	target_link_libraries(pyloader dl)
endif()
