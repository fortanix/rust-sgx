FROM ubuntu:24.04 AS sgx_sdk

# Install user
RUN useradd -rm -d /home/ppid-tool -s /bin/bash -g root -G sudo -u 1010 ppid-tool
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN echo 'ppid-tool:ppid-tool' | chpasswd
USER ppid-tool
WORKDIR /home/ppid-tool

# Install SGX Dev tools
USER root
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    gnupg \
    wget \
    sudo

# App build time dependencies
RUN apt-get update
RUN apt-get install -y build-essential

WORKDIR /opt/intel
RUN wget https://download.01.org/intel-sgx/sgx-linux/2.25/distro/ubuntu24.04-server/sgx_linux_x64_sdk_2.25.100.3.bin
RUN chmod +x sgx_linux_x64_sdk_2.25.100.3.bin
RUN echo 'yes' | ./sgx_linux_x64_sdk_2.25.100.3.bin

# Install SGX runtime libraries
USER root
RUN echo 'deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
RUN wget https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
RUN cat intel-sgx-deb.key | sudo tee /etc/apt/keyrings/intel-sgx-keyring.asc > /dev/null
RUN apt-get update
RUN apt-get install -y libsgx-urts

# Preparing to build PCKIDRetrievalTool
FROM sgx_sdk
USER root

WORKDIR ppid-tool
COPY Enclave Enclave
COPY pce pce
COPY main.c main.c
COPY Makefile Makefile

RUN source /opt/intel/sgxsdk/environment && make

ENTRYPOINT bash