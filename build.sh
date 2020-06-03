#!/bin/bash -e
cd "$(dirname "$0")"
if [ "$1" == "clean" ]; then
	echo "Removing build directory..."
	rm -r build
	exit 0
elif [ ! -z "$1" ] && [ -f "$1" ]; then
	TOOLCHAINFILE="-DCMAKE_TOOLCHAIN_FILE=$1"
fi
[ ! -d build ] && mkdir build
cd build
cmake .. ${TOOLCHAINFILE}
cmake --build . -- -j$(nproc)
