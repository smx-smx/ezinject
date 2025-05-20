add_ezinject_library(pyloader
	SOURCES pyloader.c
)
if(EZ_TARGET_POSIX)
	target_link_libraries(pyloader dl)
endif()
