add_ezinject_library(dummy
	#USE_LH
	SOURCES libdummy.c
)
target_compile_definitions(dummy PRIVATE __USE_MINGW_ANSI_STDIO=0)
if(EZ_TARGET_WINDOWS)
	target_link_options(dummy PRIVATE "LINKER:-entry=MyDllMainCRTStartup")
endif()

set(required_libs "")
if(NOT ANDROID AND EZ_TARGET_POSIX)
	list(APPEND required_libs dl)
endif()

if(EZ_ARCH_MIPS AND UCLIBC_OLD)
	message(WARNING
		" uClibc old has a bug with GOT relocation handling.\n"
		" Using global data in hooks might lead to segfaults.\n"
	)
endif()

target_link_libraries(dummy ${required_libs})

add_executable(target target.c)
target_include_directories(target PRIVATE ${EZINJECT_INCLUDE_DIRS})
# export exe symbols for dlsym (LH will use dlsym to find the function to hook)
if(NOT EZ_TARGET_DARWIN AND NOT EZ_TARGET_WINDOWS)
	target_link_options(target PRIVATE "LINKER:-export-dynamic")
endif()

INSTALL(TARGETS target)

if(EZ_TARGET_POSIX)
	add_executable(target_dl target_dl.c)
	target_link_libraries(target_dl ${required_libs})
	target_include_directories(target_dl PRIVATE ${EZINJECT_INCLUDE_DIRS})
	INSTALL(TARGETS target_dl)
endif()
