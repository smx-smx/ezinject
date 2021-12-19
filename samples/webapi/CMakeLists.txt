add_ezinject_library(webapi
	#USE_LOG
	SOURCES webapi.c
)
target_link_libraries(webapi dl pthread)