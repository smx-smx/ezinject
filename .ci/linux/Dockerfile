FROM gcc:10.3.0-buster

RUN wget -O cmake.sh https://cmake.org/files/v3.14/cmake-3.14.0-Linux-x86_64.sh \
	&& sh cmake.sh --skip-license --exclude-subdir --prefix=/usr/local \
	&& rm cmake.sh

RUN apt-get update \
	&& apt-get install -y libcapstone-dev \
	&& apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN cd /tmp && curl -LO https://dl.google.com/android/repository/android-ndk-r14b-linux-x86_64.zip \
	&& cd /opt && unzip -q /tmp/android-ndk-r14b-linux-x86_64.zip \
	&& python /opt/android-ndk-r14b/build/tools/make_standalone_toolchain.py \
        --arch arm \
        --api 9 \
        --install-dir /opt/android-ndk-r14b-android-9 \
	&& python /opt/android-ndk-r14b/build/tools/make_standalone_toolchain.py \
        --arch arm64 \
        --api 21 \
        --install-dir /opt/android-ndk-r14b-android-21-arm64 \
	&& rm /tmp/android-ndk-r14b-linux-x86_64.zip

RUN mkdir -p /opt/arm-buildroot-linux-uclibcgnueabi && \
	cd /opt/arm-buildroot-linux-uclibcgnueabi && \
	curl -L -o - https://github.com/smx-smx/arm-buildroot-linux-uclibcgnueabi/archive/refs/heads/master.tar.gz |\
	tar --strip-components=1 -xzf -

RUN dpkg --add-architecture i386 \
	&& apt-get update \
	&& apt-get install -y libc6:i386 libstdc++6:i386 libgcc1:i386 zlib1g:i386 libncurses5:i386 \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/trendchip/mips-linux-uclibc && \
	cd /opt/trendchip/mips-linux-uclibc && \
	curl -L -o - https://github.com/smx-smx/trendchip-mips-linux-uclibc/archive/refs/heads/master.tar.gz |\
	tar --strip-components=1 -xzf -

RUN mkdir -p /opt/ttgo/gcc-3.3.4_glibc-2.3.2 && \
	cd /opt/ttgo/gcc-3.3.4_glibc-2.3.2 && \
	curl -L -o - https://github.com/smx-smx/ttgo-arm-linux/archive/refs/heads/master.tar.gz |\
	tar --strip-components=1 -xzf -

RUN mkdir -p /opt/arm-lgtv-linux-gnueabi_sdk-buildroot && \
	cd /opt/arm-lgtv-linux-gnueabi_sdk-buildroot && \
	curl -L -o - https://github.com/openlgtv/buildroot-nc4/releases/download/webos-2974f83/arm-lgtv-linux-gnueabi_sdk-buildroot.tar.gz |\
	tar --strip-components=1 -xzf - && \
	./relocate-sdk.sh && \
	(rm bin/cmake* || true)
