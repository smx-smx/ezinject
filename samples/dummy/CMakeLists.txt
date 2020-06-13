add_executable(target target.c)
add_ezinject_library(dummy
	USE_LH USE_LOG
	SOURCES libdummy.c
)
target_link_libraries(dummy dl)

add_executable(target_dl target_dl.c)
target_link_libraries(target_dl dl)