PHP_PREFIX=/mnt/ExtData/php-8.1.2/out-x64
FRIDA_PREFIX=/mnt/ExtData/frida-gum/build/out/usr/local

if [ ! -z "$CLEAN" ]; then
	./build.sh clean
fi

./build.sh \
	-DENABLE_PHP_SAMPLE=ON \
	-DPHP_PREFIX=${PHP_PREFIX} \
	-DUSE_CAPSTONE=OFF \
	-DUSE_FRIDA_GUM=ON \
	-DFRIDA_PREFIX=${FRIDA_PREFIX}
