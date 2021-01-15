add_ezinject_library(dummy_cpp
	USE_LH
	#USE_LOG
	SOURCES libdummy.cpp
)

set(required_libs "")
if(NOT ANDROID)
	list(APPEND required_libs dl)
endif()

target_link_libraries(dummy_cpp ${required_libs})

add_executable(target_cpp target.cpp)
target_link_libraries(target_cpp ${required_libs})

