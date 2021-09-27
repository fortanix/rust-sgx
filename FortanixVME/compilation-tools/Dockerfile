FROM ubuntu:20.04
RUN apt-get update
RUN apt-get -y --no-install-recommends install \
    ca-certificates \
    g++ \
    git \
    make \
    patch \
    wget \
    xz-utils


WORKDIR /tmp
COPY ./musl_toolchain.sh /tmp
RUN ./musl_toolchain.sh
