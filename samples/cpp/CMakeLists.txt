add_ezinject_library(dummy_cpp
	USE_LH
	#USE_LOG
	SOURCES libdummy.cpp
)
target_link_libraries(dummy_cpp dl stdc++)

add_executable(target_cpp target.cpp)
target_link_libraries(target_cpp dl)

