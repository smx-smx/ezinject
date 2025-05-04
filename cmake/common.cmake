macro(static_library_name var name)
	set(${var} ${CMAKE_STATIC_LIBRARY_PREFIX}${name}${CMAKE_STATIC_LIBRARY_SUFFIX})
endmacro()

function(find_static_library var name)
	static_library_name(_lib_name "${name}")
	unset(_lib_path CACHE)
	find_library(_lib_path NAMES ${_lib_name})
	set(${var} ${_lib_path} PARENT_SCOPE)
endfunction()

function(extproj_getprop project property variable)
	ExternalProject_Get_Property(${project} ${property})
	set(_value "${${property}}")
	set(${variable} ${_value} PARENT_SCOPE)
endfunction()

function(escape_for_regex input output)
	string(REGEX REPLACE "([][+.*()^])" "\\\\\\1" temp "${input}")
	set(${output} "${temp}" PARENT_SCOPE)
endfunction()

function(_get_lib_regexps out_var)
	set(_lib_strip_prefixes "")
	set(_lib_strip_suffixes "")

	list(APPEND _lib_strip_prefixes
		"${CMAKE_SHARED_LIBRARY_PREFIX}"
		"${CMAKE_STATIC_LIBRARY_PREFIX}"
	)
	list(APPEND _lib_strip_suffixes
		"${CMAKE_SHARED_LIBRARY_SUFFIX}"
		"${CMAKE_STATIC_LIBRARY_SUFFIX}"
	)
	list(REMOVE_DUPLICATES _lib_strip_prefixes)
	list(REMOVE_DUPLICATES _lib_strip_suffixes)

	set(_regexps "")
	foreach(re ${_lib_strip_prefixes})
		escape_for_regex("${re}" re)
		list(APPEND _regexps "^${re}")
	endforeach()
	
	foreach(re ${_lib_strip_suffixes})
		escape_for_regex("${re}" re)
		list(APPEND _regexps "${re}$")
	endforeach()

	set(${out_var} "${_regexps}" PARENT_SCOPE)
endfunction()

function(convert_to_static)
	cmake_parse_arguments(ARG "" "TARGET" "LIBRARIES;SKIP;EXCLUSIONS;RESULT_VARIABLE" ${ARGN})

	_get_lib_regexps(_regexps)
	
	foreach(re ${_lib_strip_suffixes})
		escape_for_regex("${re}" re)
		list(APPEND _regexps "${re}$")
	endforeach()

	if(ARG_TARGET)
		# get library names
		get_property(_libraries
			TARGET ${ARG_TARGET} PROPERTY
			INTERFACE_LINK_LIBRARIES)
	elseif(ARG_LIBRARIES)
		set(_libraries ${ARG_LIBRARIES})
	else()
		message(FATAL_ERROR "invalid arguments")
	endif()

	list(REMOVE_DUPLICATES _libraries)

	set(_new_libraries "")

	# construct new list
	foreach(lib ${_libraries})
		get_filename_component(lib_name "${lib}" NAME)
		set(_old_lib_filename "${lib_name}")

		foreach(re ${_regexps})
			string(REGEX REPLACE "${re}" "" lib_name "${lib_name}")
		endforeach()

		set(var_name "${lib_name}_LIBRARY")
		
		if("${lib_name}" IN_LIST ARG_SKIP)
			continue()
		endif()

		# check if this library should NOT be linked statically
		if("${lib_name}" IN_LIST ARG_EXCLUSIONS)
			find_library(${var_name} ${lib_name})
		else()
			find_static_library(${var_name} ${lib_name})
		endif()

		if(NOT ${var_name})
			message(FATAL_ERROR "library ${lib_name} not found")
		endif()

		set(lib "${${var_name}}")

		get_filename_component(_new_lib_filename "${lib}" NAME)
		if(NOT "${_old_lib_filename}" STREQUAL "${_new_lib_filename}")
			message(STATUS "convert_to_static ${lib_name} : ${_old_lib_filename} => ${_new_lib_filename}")
		endif()
		list(APPEND _new_libraries "${lib}")
	endforeach()

	set(${ARG_RESULT_VARIABLE} "${_new_libraries}" PARENT_SCOPE)
endfunction()