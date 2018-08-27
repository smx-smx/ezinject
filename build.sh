#!/bin/sh -e
cd "$(dirname "$0")"
if [ "$1" == "clean" ]; then
	echo "Removing build directory..."
	rm -r build
	exit 0
elif [ "$1" == "arm" ]; then
	TOOLCHAINFILE="-DCMAKE_TOOLCHAIN_FILE=arm.cmake"
fi
[ ! -d build ] && mkdir build
cd build
cmake .. ${TOOLCHAINFILE:+"$TOOLCHAINFILE"} # Only pass the parameter if it's set
cmake --build . -- -j$(nproc)
