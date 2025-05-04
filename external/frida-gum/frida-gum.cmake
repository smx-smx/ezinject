find_package(PkgConfig REQUIRED)

set(frida_src ${CMAKE_CURRENT_LIST_DIR})
set(frida_bin ${CMAKE_BINARY_DIR}/external/frida-gum)
set(frida_out ${frida_bin}/out)

include(ProcessorCount)
ProcessorCount(NCPU)

execute_process(
	COMMAND ${CMAKE_COMMAND}
		-G${CMAKE_GENERATOR}
		-S ${frida_src}
		-B ${frida_bin}
		-DTOP=${CMAKE_SOURCE_DIR}
		-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
		-DCMAKE_INSTALL_PREFIX=${frida_out}
)
execute_process(
	COMMAND ${CMAKE_COMMAND}
	--build ${frida_bin}
	--parallel ${NCPU}
)
execute_process(
	COMMAND ${CMAKE_COMMAND}
	--install ${frida_bin}
)

cmake_path(
	CONVERT "$ENV{PKG_CONFIG_PATH}"
	TO_CMAKE_PATH_LIST pkg_config_path_list
	NORMALIZE
)

file(READ "${frida_bin}/pkg_config_path.txt" frida_pkg_config)
string(STRIP "${frida_pkg_config}" frida_pkg_config)

foreach(itm ${pkg_config_path_list})
	list(APPEND frida_pkg_config ${itm})
endforeach()

cmake_path(
	CONVERT "${frida_pkg_config}"
	TO_NATIVE_PATH_LIST pkg_config_path_list_str
	NORMALIZE
)
set(ENV{PKG_CONFIG_PATH} "${pkg_config_path_list_str}")

# find just compiled library
pkg_check_modules(FRIDA_GUM
	IMPORTED_TARGET frida-gum-1.0 GLOBAL
	REQUIRED
)

add_link_options(-Wl,--gc-sections)