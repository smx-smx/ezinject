FROM gcc:10.3.0-buster

RUN wget -O cmake.sh https://cmake.org/files/v3.20/cmake-3.20.6-linux-aarch64.sh \
	&& sh cmake.sh --skip-license --exclude-subdir --prefix=/usr/local \
	&& rm cmake.sh

RUN apt-get update \
	&& apt-get install -y libcapstone-dev \
	&& apt-get clean \
    && rm -rf /var/lib/apt/lists/*
