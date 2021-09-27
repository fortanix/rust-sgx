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
COPY ./fortanixvme_toolchain.sh /tmp
RUN ./fortanixvme_toolchain.sh
