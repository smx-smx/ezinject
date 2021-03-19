#!/bin/bash
set -m

export PATH=/opt/android-ndk-r14b-android-21-arm64/bin:$PATH

#LIBC_VARIANT=android-2
#LIBC_VARIANT=android-5
LIBC_VARIANT=android-10

../build.sh $PWD/arm64-android.cmake \
	-DEZ_LIBC=bionic \
	-DEZ_LIBC_VARIANT=${LIBC_VARIANT} \
	-DENABLE_STATIC=OFF \
	-DANDROID_ABI=arm64-v8a \
	-DCMAKE_SYSTEM_VERSION=21 \
	-DUSE_ANDROID_ASHMEM=ON \
&& \
adb push \
	../build/ezinject \
	../build/samples/dummy/{libdummy.so,target} \
	/data/local/tmp

if [ ! $? -eq 0 ]; then
	exit 1
fi

adb shell 'kill -9 $(pidof ezinject)'
adb shell 'kill -9 $(pidof target)'
adb shell /data/local/tmp/target &
sleep 2
adb shell su -c '"/data/local/tmp/ezinject $(pidof target) /data/local/tmp/libdummy.so 1 2 3 4"'
fg %1