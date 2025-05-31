if(EZ_TARGET_POSIX)
	add_library(os_posix remote.c)
	add_library(os_posix_util util.c)
	target_link_libraries(${EZINJECT_TARGET}
		os_posix
		os_posix_util)
endif()

add_library(os_posix_shellcode inject.c)

target_link_libraries(${EZINJECT_TARGET} os_posix_shellcode)
