add_ezinject_library(dotnetcore
	#USE_LOG
	SOURCES
		dotnetcore.c
		util.c
)
target_link_libraries(dotnetcore dl)