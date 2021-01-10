add_executable(target target.c)
add_ezinject_library(dummy
	USE_LH
	#USE_LOG
	SOURCES libdummy.c
)

set(required_libs "")
if(NOT ANDROID)
	list(APPEND required_libs dl)
endif()

target_link_libraries(dummy ${required_libs})

add_executable(target_dl target_dl.c)
target_link_libraries(target_dl ${required_libs})