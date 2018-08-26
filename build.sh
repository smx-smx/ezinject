#!/bin/sh -e
cd "$(dirname "$0")"
if [ "$1" == "clean" ]; then
	echo "Removing build directory..."
	rm -r build
else
	[ ! -d build ] && mkdir build
	cd build
	cmake ..
	cmake --build . -- -j$(nproc)
fi