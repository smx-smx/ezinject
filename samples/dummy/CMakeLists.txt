add_executable(target target.c)

set(ARG_USE_LH "")
if(NOT EZ_TARGET_WINDOWS)
	set(ARG_USE_LH "USE_LH")
endif()

add_ezinject_library(dummy
	${ARG_USE_LH}
	#USE_LOG
	SOURCES libdummy.c
)

set(required_libs "")
if(NOT ANDROID)
	list(APPEND required_libs dl)
endif()

if(EZ_ARCH_MIPS AND UCLIBC_OLD)
	message(WARNING
		" uClibc old has a bug with GOT relocation handling.\n"
		" Using global data in hooks might lead to segfaults.\n"
	)
endif()

target_link_libraries(dummy ${required_libs})

if(EZ_TARGET_POSIX)
	add_executable(target_dl target_dl.c)
	target_link_libraries(target_dl ${required_libs})
endif()