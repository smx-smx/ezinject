#!/bin/bash
set -m

#-DEZ_LIBC=uclibc \
#-DEZ_LIBC_VARIANT=new \

ssh root@192.168.1.1 'kill -9 $(pidof ezinject)'
ssh root@192.168.1.1 'kill -9 $(pidof target)'

../build.sh $PWD/arm-buildroot-bcm-uclibc.cmake \
	-DENABLE_STATIC=OFF \
&& \
scp \
	../build/ezinject \
	../build/samples/dummy/{libdummy.so,target} \
	root@192.168.1.1:/tmp/

if [ ! $? -eq 0 ]; then
	exit 1
fi

expect -f uclibc.expect
