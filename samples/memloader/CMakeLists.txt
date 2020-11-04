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

add_dependencies(memloader module)
set_target_properties(memloader PROPERTIES COMPILE_DEFINITIONS "MODULE_FILE=\"$<TARGET_FILE:module>\"")
target_link_libraries(memloader dl)