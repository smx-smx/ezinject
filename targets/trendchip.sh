#!/bin/bash
set -m

#-DEZ_LIBC=uclibc \
#-DEZ_LIBC_VARIANT=old \

ssh admin@192.168.0.2 'kill -9 $(pidof ezinject)'
ssh admin@192.168.0.2 'kill -9 $(pidof target)'

../build.sh $PWD/trendchip.cmake \
	-DENABLE_STATIC=OFF \
&& \
tar -cvf - \
	-C ../build ezinject \
	-C ../build/samples/dummy {libdummy.so,target} \
| ssh admin@192.168.0.2 'tar -C /tmp -xvf -'

if [ ! $? -eq 0 ]; then
	exit 1
fi

expect -f trendchip.expect
