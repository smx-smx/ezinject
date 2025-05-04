cmake_minimum_required(VERSION 3.20)
project(frida-gum)

include(${TOP}/cmake/common.cmake)
include(ExternalProject)

execute_process(
	COMMAND ${CMAKE_C_COMPILER} -dumpmachine
	OUTPUT_VARIABLE host_machine
	OUTPUT_STRIP_TRAILING_WHITESPACE
)

ExternalProject_Add(
	frida-libdwarf
	GIT_REPOSITORY https://github.com/frida/libdwarf.git
	GIT_TAG 50e3115b340c6a58d2f61af96f120a9d111ac024
	GIT_PROGRESS ON
	GIT_SHALLOW ON
	UPDATE_COMMAND ""
	CONFIGURE_COMMAND
	meson setup --reconfigure
		--prefix <INSTALL_DIR>
		<BINARY_DIR> <SOURCE_DIR>
	BUILD_COMMAND
		meson compile
	INSTALL_COMMAND
		meson install
)

ExternalProject_Add(
	frida-capstone
	GIT_REPOSITORY https://github.com/frida/capstone.git
	GIT_TAG e98746112da0a40b2ccd0340db0d20cca5f97950
	GIT_PROGRESS ON
	GIT_SHALLOW ON
	CONFIGURE_COMMAND
		meson setup --reconfigure
			--prefix <INSTALL_DIR>
			<BINARY_DIR> <SOURCE_DIR>
	BUILD_COMMAND
		meson compile
	INSTALL_COMMAND
		meson install
)


extproj_getprop(frida-capstone INSTALL_DIR frida_capstone_dir)
extproj_getprop(frida-libdwarf INSTALL_DIR frida_libdwarf_dir)

cmake_path(
	CONVERT "$ENV{PKG_CONFIG_PATH}"
	TO_CMAKE_PATH_LIST pkg_config_path_list
	NORMALIZE
)
list(PREPEND pkg_config_path_list
	${frida_libdwarf_dir}/lib/${host_machine}/pkgconfig
	${frida_capstone_dir}/lib/${host_machine}/pkgconfig
)
cmake_path(
	CONVERT "${pkg_config_path_list}"
	TO_NATIVE_PATH_LIST pkg_config_path_list_str
	NORMALIZE
)

ExternalProject_Add(
	frida-gum
	GIT_REPOSITORY https://github.com/frida/frida-gum.git
	GIT_TAG 617c450b4f347df349b96a9dcdc7f837d09e48be
	GIT_PROGRESS ON
	GIT_SHALLOW ON
	CONFIGURE_COMMAND
		PKG_CONFIG_PATH=${pkg_config_path_list_str}
		meson setup
			-Dgumjs=disabled
			-Dgumpp=disabled
			-Dtests=disabled
			--prefix <INSTALL_DIR>
			--libdir lib
			-Ddefault_library=static
			<BINARY_DIR> <SOURCE_DIR>
	BUILD_COMMAND
		meson compile
			frida-gum-1.0
			frida-gum-heap-1.0
	INSTALL_COMMAND
		meson install
	INSTALL_DIR ${CMAKE_INSTALL_PREFIX}
)

add_dependencies(frida-gum frida-capstone)
add_dependencies(frida-gum frida-libdwarf)

extproj_getprop(frida-gum INSTALL_DIR frida_install_dir)

set(frida_pkg_config_list "")
list(APPEND frida_pkg_config_list
	${frida_libdwarf_dir}/lib/${host_machine}/pkgconfig
	${frida_capstone_dir}/lib/${host_machine}/pkgconfig
	${frida_install_dir}/lib/pkgconfig
)

add_custom_command(
	OUTPUT ${CMAKE_BINARY_DIR}/pkg_config_path.txt
	COMMAND ${CMAKE_COMMAND} -E echo "${frida_pkg_config_list}" > ${CMAKE_BINARY_DIR}/pkg_config_path.txt
	VERBATIM
)
add_custom_target(print_pkg_config_path ALL
	DEPENDS ${CMAKE_BINARY_DIR}/pkg_config_path.txt
)
