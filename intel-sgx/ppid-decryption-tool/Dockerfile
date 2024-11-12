From ubuntu:focal as sgx_sdk

RUN apt-get update
RUN DEBIAN_FRONTEND="noninteractive" TZ="America/New_York" apt-get install -y git build-essential python

# Install user
RUN useradd -rm -d /home/ppid-tool -s /bin/bash -g root -G sudo -u 1000 ppid-tool
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN echo 'ppid-tool:ppid-tool' | chpasswd
USER ppid-tool
WORKDIR /home/ppid-tool

# Install SGX Dev tools
USER root
RUN apt-get update
RUN DEBIAN_FRONTEND="noninteractive" TZ="America/New_York" apt-get install -y build-essential ocaml ocamlbuild automake autoconf libtool wget python-is-python3 libssl-dev git cmake perl unzip libboost-dev libboost-system-dev libboost-thread-dev

USER ppid-tool
RUN git clone https://github.com/intel/linux-sgx.git
WORKDIR linux-sgx
RUN make preparation
RUN ls external/toolset/
USER root
RUN cp external/toolset/ubuntu20.04/* /usr/local/bin
USER ppid-tool

RUN make sdk
RUN make sdk_install_pkg
RUN ls linux/installer/bin

USER root
RUN apt-get install -y pkg-config
RUN bash -c "echo yes | ./$(find linux/installer/bin/ -name 'sgx_linux_x64_sdk*')"

# Install SGX DCAP primitives
USER root
RUN apt-get install -y protobuf-c-compiler libprotobuf-c-dev protobuf-compiler
RUN apt-get install -y libboost-dev libboost-system-dev
RUN apt-get install -y libcurl4-openssl-dev
USER ppid-tool
RUN git clone https://github.com/intel/SGXDataCenterAttestationPrimitives.git
WORKDIR SGXDataCenterAttestationPrimitives
RUN git submodule update  --init
RUN QuoteGeneration/download_prebuilt.sh
RUN source /home/ppid-tool/linux-sgx/sgxsdk/environment && make

WORKDIR tools/PCKCertSelection
USER root
RUN apt-get install -y zip
USER ppid-tool
RUN make

USER root
RUN apt-get install -y debhelper
# Bugfix: The `make deb_pkg` command results in a check whether systemd is installed
RUN mkdir -p /run/systemd/system/
USER ppid-tool
WORKDIR ../../tools/SGXPlatformRegistration
RUN source /home/ppid-tool/linux-sgx/sgxsdk/environment && make
RUN source /home/ppid-tool/linux-sgx/sgxsdk/environment && make deb_pkg
USER root
RUN bash -c 'rm -rf /run/systemd'

# installed to:
# ~/linux-sgx/SGXDataCenterAttestationPrimitives/tools/SGXPlatformRegistration/build/installer/
From sgx_sdk as ppid-runtime
# Install SGX runtime libraries
USER root
RUN apt-get install sudo
RUN echo 'deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
RUN wget https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
RUN mkdir /etc/apt/keyrings
RUN cat intel-sgx-deb.key | sudo tee /etc/apt/keyrings/intel-sgx-keyring.asc > /dev/null
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get update
RUN apt-get install -y libsgx-urts libsgx-epid libsgx-quote-ex libsgx-dcap-ql

# Setup aesmd service in container
USER root
RUN bash -c 'mkdir /var/run/aesmd'
RUN bash -c 'chown -c ppid-tool /var/run/aesmd'

# Preparing to run PCKIDRetrievalTool
USER root
RUN bash -c 'apt-get install -y screen'

From ppid-runtime
USER root

WORKDIR ppid-tool
COPY Enclave Enclave
COPY pce pce
COPY main.c main.c
COPY Makefile Makefile

RUN source /home/ppid-tool/linux-sgx/sgxsdk/environment && make

ENTRYPOINT bash
