#!/bin/sh
set -e

mkdir -p m4 build-aux
autoreconf -fi

echo ""
echo "Autotools bootstrap complete."
echo "Run: mkdir build && cd build && ../configure && make"
