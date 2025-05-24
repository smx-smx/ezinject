#!/usr/bin/env bash
set -e

if [[ "$OSTYPE" == "freebsd"* ]] || [[ "$OSTYPE" == "darwin"* ]]; then
	jobs=$(sysctl -n hw.ncpu)
else
	jobs=$(nproc)
fi

if [[ "$OSTYPE" == "msys" ]]; then
	generator="MSYS Makefiles"
else
	generator="Unix Makefiles"
fi

cd "$(dirname "$0")"
if [ "$1" == "clean" ]; then
	echo "Removing build directory..."
	[ -d build ] && rm -rf build
	[ -d build_samples ] && rm -rf build_samples
	exit 0
elif [ ! -z "$1" ] && [ -f "$1" ]; then
	toolchain_file_abspath="$(readlink -f "$1")"
	TOOLCHAINFILE="-DCMAKE_TOOLCHAIN_FILE='${toolchain_file_abspath}'"
	shift
fi

cmake \
	-G "${generator}" \
	-B build "${TOOLCHAINFILE}" \
	-DCMAKE_INSTALL_PREFIX="$PWD/build/out" "$@"
cmake --build build -- -j${jobs} -k
cmake --install build

# check if the SDK works properly by building the samples again
# this time out-of-tree 
if [ ! -z "${EZSDK_SMOKE_TEST}" ]; then
	echo "======== building samples ========"
	cmake \
		-G "${generator}" \
		-S samples \
		-B build_samples "${TOOLCHAINFILE}" \
		-DOUT_OF_TREE=ON \
		-DEZINJECT_PREFIX="$PWD/build/out" \
		-DCMAKE_INSTALL_PREFIX="$PWD/build_samples/out" "$@"
	cmake --build build_samples -- -j${jobs} -k
	cmake --install build_samples
fi
