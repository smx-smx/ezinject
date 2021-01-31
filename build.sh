#!/usr/bin/env bash
set -e

if [[ "$OSTYPE" == "freebsd"* ]] || [[ "$OSTYPE" == "darwin"* ]]; then
	jobs=$(sysctl -n hw.ncpu)
else
	jobs=$(nproc)
fi

cd "$(dirname "$0")"
if [ "$1" == "clean" ]; then
	echo "Removing build directory..."
	rm -r build
	exit 0
elif [ ! -z "$1" ] && [ -f "$1" ]; then
	TOOLCHAINFILE="-DCMAKE_TOOLCHAIN_FILE=$1"
	shift
fi
[ ! -d build ] && mkdir build
cd build
cmake .. ${TOOLCHAINFILE} $*
cmake --build . -- -j${jobs}
