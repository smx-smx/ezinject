find_package(PkgConfig REQUIRED)
pkg_check_modules(MONO REQUIRED mono-2)

include_directories(
	${MONO_INCLUDE_DIRS}
)

add_ezinject_library(mono
	USE_LOG
	USE_LH
	SOURCES
		monohost.c
		util.c
)
set_target_properties(mono PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_compile_options(mono PUBLIC -nostdlib)

target_link_libraries(mono dl
	 #-Wl,-Bsymbolic-functions
)

