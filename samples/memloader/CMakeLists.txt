add_library(module SHARED module.c)

macro(handle_asm_file file)
	set_property(SOURCE "${file}" PROPERTY LANGUAGE C)
	set_property(SOURCE "${file}" PROPERTY COMPILE_DEFINITIONS __ASSEMBLY__)
endmacro()

handle_asm_file(memloader.S)

add_ezinject_library(memloader
	SOURCES
		memloader.c
		memloader.S
)

set(MODULE_FILE $<TARGET_FILE:module>)

# if the module file changed, rebuild memloader.S
add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/memloader.S
	COMMAND ${CMAKE_COMMAND} -E touch ${CMAKE_CURRENT_SOURCE_DIR}/memloader.S
	DEPENDS ${MODULE_FILE}
)

add_custom_target(touch_memloader ALL
	DEPENDS ${MODULE_FILE}
)

# update memloader only after module has been compiled
add_dependencies(touch_memloader module)
add_dependencies(memloader module)

set_target_properties(memloader PROPERTIES COMPILE_DEFINITIONS "MODULE_FILE=\"${MODULE_FILE}\"")
target_link_libraries(memloader dl)