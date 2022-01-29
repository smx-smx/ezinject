find_package(PHP REQUIRED)
add_definitions(${PHP_INCLUDE_DIRS})

add_ezinject_library(php
	USE_LH
	SOURCES
		php_embed.c
)
if(PHP_PREFIX)
	target_include_directories(php PUBLIC
		${PHP_PREFIX}/include/php
		${PHP_PREFIX}/include/php/main
		${PHP_PREFIX}/include/php/TSRM
		${PHP_PREFIX}/include/php/Zend
	)
endif()

#set_target_properties(php PROPERTIES
#	LINK_SEARCH_START_STATIC 1
#)

set_target_properties(php PROPERTIES
	POSITION_INDEPENDENT_CODE ON
)

find_library(PHP_EMBED_LIBRARY
	PATHS ${PHP_PREFIX}
	PATH_SUFFIXES lib
	NAMES
		php
		php7
	REQUIRED
	NO_CMAKE_FIND_ROOT_PATH
	NO_DEFAULT_PATH
)

message("=> ${PHP_EMBED_LIBRARY}")

find_library(UTIL_LIBRARY NAMES
	libutil.a
	util
	REQUIRED
)
find_library(CRYPT_LIBRARY NAMES
	libcrypt.a
	crypt
	REQUIRED
)
find_library(RESOLV_LIBRARY NAMES
	resolv
	REQUIRED
)
find_library(FFI_LIBRARY NAMES
	libffi.a
	ffi
	REQUIRED
)
find_library(PTHREAD_LIBRARY NAMES
	pthread
	REQUIRED
)

target_link_libraries(php 
	${PHP_EMBED_LIBRARY}
	${FFI_LIBRARY}
	${PTHREAD_LIBRARY}
	${UTIL_LIBRARY}
	resolv rt m
	dl 
)
target_link_options(php PRIVATE
	-static-libgcc
)