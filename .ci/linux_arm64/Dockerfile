FROM gcc:10.3.0-buster

RUN sed -Ei 's/(deb|security)\.debian\.org/archive.debian.org/g' /etc/apt/sources.list \
	&& sed -i '/buster-updates/d' /etc/apt/sources.list \
	&& echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99ignore-valid-until

RUN wget -O cmake.sh https://cmake.org/files/v3.20/cmake-3.20.6-linux-aarch64.sh \
	&& sh cmake.sh --skip-license --exclude-subdir --prefix=/usr/local \
	&& rm cmake.sh

RUN apt-get update \
	&& apt-get install -y libcapstone-dev \
	&& apt-get clean \
    && rm -rf /var/lib/apt/lists/*
