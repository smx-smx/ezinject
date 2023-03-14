cmake_minimum_required(VERSION 3.16)
project(frida-gum)

include(ExternalProject)
ExternalProject_Add(
	frida-gum
	GIT_REPOSITORY https://github.com/frida/frida-gum.git
	GIT_TAG main
	GIT_PROGRESS ON
	CONFIGURE_COMMAND
		meson
			-Dgumjs=disabled
			-Dgumpp=disabled
			-Dtests=false
			--prefix <INSTALL_DIR>
			--libdir lib
			-Ddefault_library=static
			${FRIDA_SRC}
	BUILD_COMMAND
		meson compile
			frida-gum-1.0
			frida-gum-heap-1.0
	INSTALL_COMMAND
		meson install
)