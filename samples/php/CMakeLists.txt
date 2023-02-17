if(USE_FRIDA_GUM)
	set(OPT_USE_LH "")
else()
	set(OPT_USE_LH "USE_LH")
endif()

add_ezinject_library(php
	${OPT_USE_LH}
	SOURCES
		php_embed.c
)

macro(static_library_name var name)
	set(${var} ${CMAKE_STATIC_LIBRARY_PREFIX}${name}${CMAKE_STATIC_LIBRARY_SUFFIX})
endmacro()

function(find_static_library var name)
	static_library_name(_lib_name "${name}")
	unset(_lib_path CACHE)
	find_library(_lib_path NAMES ${_lib_name})
	set(${var} ${_lib_path} PARENT_SCOPE)
endfunction()

find_program(PHP_CONFIG_EXECUTABLE NAMES
	php-config
	HINTS
		# use php-config from the sysroot (it's a shell script)
		${CMAKE_SYSROOT}
	PATH_SUFFIXES
		bin
		usr/bin
	REQUIRED
)
message(STATUS "php-config: ${PHP_CONFIG_EXECUTABLE}")

execute_process(
	COMMAND ${PHP_CONFIG_EXECUTABLE} --includes
	OUTPUT_VARIABLE PHP_INCLUDE_DIRS OUTPUT_STRIP_TRAILING_WHITESPACE
)
execute_process(
	COMMAND ${PHP_CONFIG_EXECUTABLE} --libs
	OUTPUT_VARIABLE PHP_LIBS OUTPUT_STRIP_TRAILING_WHITESPACE
)

string(REPLACE "-I" "" PHP_INCLUDE_DIRS ${PHP_INCLUDE_DIRS})
separate_arguments(PHP_INCLUDE_DIRS)

string(REPLACE "-l" "" PHP_LIBS ${PHP_LIBS})
separate_arguments(PHP_LIBS)

set_target_properties(php PROPERTIES
	POSITION_INDEPENDENT_CODE ON
)


static_library_name(_php_static php)
static_library_name(_php7_static php7)

find_library(PHP_EMBED_LIBRARY
	PATHS
		${PHP_PREFIX}
		${CMAKE_SYSROOT}
	PATH_SUFFIXES
		lib
		usr/lib
	NAMES
		${_php_static}
		${_php7_static}
		php php7
	REQUIRED
	# allow everywhere on the FS, to consider ${PHP_PREFIX} globally
	NO_CMAKE_FIND_ROOT_PATH
	NO_DEFAULT_PATH
)

# list of libraries that we want to use dynamically
set(_static_excluded
	resolv rt dl m pthread crypt
)

set(_libphp_libs "")
foreach(lib ${PHP_LIBS})
	set(var_name "${lib}_LIBRARY")
	if("${lib}" IN_LIST _static_excluded)
		find_library(${var_name} NAMES ${lib})
	else()
		find_static_library(${var_name} ${lib})
	endif()
	message(STATUS "php ${lib} [${var_name}] = ${${var_name}}")
	if(NOT ${var_name})
		message(WARNING "library \"${lib}\" not found")
	else()
		list(APPEND _libphp_libs "${${var_name}}")
	endif()
endforeach()

add_library(libphp UNKNOWN IMPORTED)
set_target_properties(libphp PROPERTIES
	IMPORTED_LOCATION "${PHP_EMBED_LIBRARY}"
	INTERFACE_INCLUDE_DIRECTORIES "${PHP_INCLUDE_DIRS}"
	INTERFACE_LINK_LIBRARIES "${_libphp_libs}"
)

target_link_libraries(php libphp dl)

if(USE_FRIDA_GUM)
	# get library names
	get_property(_frida_libs TARGET PkgConfig::FRIDA_GUM_STATIC PROPERTY INTERFACE_LINK_LIBRARIES)

	set(_frida_libraries "")

	# construct new list
	foreach(lib ${_frida_libs})
		get_filename_component(lib_name "${lib}" NAME)
		set(_old_lib_filename "${lib_name}")

		string(REGEX REPLACE "^${CMAKE_SHARED_LIBRARY_PREFIX}" "" lib_name "${lib_name}")
		string(REGEX REPLACE "^${CMAKE_STATIC_LIBRARY_PREFIX}" "" lib_name "${lib_name}")
		string(REGEX REPLACE "${CMAKE_SHARED_LIBRARY_SUFFIX}$" "" lib_name "${lib_name}")
		string(REGEX REPLACE "${CMAKE_STATIC_LIBRARY_SUFFIX}$" "" lib_name "${lib_name}")

		set(var_name "${lib_name}_LIBRARY")
		if("${lib_name}" IN_LIST _static_excluded)
			find_library(${var_name} ${lib_name})
		else()
			find_static_library(${var_name} ${lib_name})
		endif()
		set(lib "${${var_name}}")

		get_filename_component(_new_lib_filename "${lib}" NAME)
		if(NOT "${_old_lib_filename}" STREQUAL "${_new_lib_filename}")
			message(STATUS "frida ${lib_name} : ${_old_lib_filename} => ${_new_lib_filename}")
		endif()
		list(APPEND _frida_libraries "${lib}")
	endforeach()

	# set new list
	set_target_properties(PkgConfig::FRIDA_GUM_STATIC
		PROPERTIES INTERFACE_LINK_LIBRARIES "${_frida_libraries}"
	)

	target_link_libraries(php PkgConfig::FRIDA_GUM_STATIC)
endif()

target_link_options(php PRIVATE
	-static-libgcc
	-Wl,--version-script,${CMAKE_CURRENT_SOURCE_DIR}/php_embed.version
)
