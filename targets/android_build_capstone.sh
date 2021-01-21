#!/bin/bash
STANDALONE="$1"
CAPSTONE_DIR="$2"
pushd "${CAPSTONE_DIR}"

export DESTDIR=out
export V=s
export CROSS=${STANDALONE}/bin/arm-linux-androideabi-
export CFLAGS="--sysroot=${STANDALONE}/sysroot"
make clean
make libcapstone.a
make install

popd