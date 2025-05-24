add_ezinject_library(dotnetcore
	SOURCES
		dotnetcore.c
		util.c
)
target_link_libraries(dotnetcore dl)
