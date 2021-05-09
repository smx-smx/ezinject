find_package(PHP REQUIRED)

add_definitions(${PHP_INCLUDE_DIRS})

find_library(PHP_EMBED_LIBRARY
	PATHS /opt/php74/lib
	NAMES php7
	REQUIRED
	NO_DEFAULT_PATH
)
message("=> ${PHP_EMBED_LIBRARY}")

add_ezinject_library(php
	USE_LH
	SOURCES
		php_embed.c
)
target_link_libraries(php ${PHP_EMBED_LIBRARY})