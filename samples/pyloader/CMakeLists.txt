add_ezinject_library(pyloader
	#USE_LOG
	SOURCES pyloader.c
)
target_link_libraries(pyloader dl)
