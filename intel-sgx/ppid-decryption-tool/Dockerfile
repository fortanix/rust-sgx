FROM ubuntu:24.04 as sgx_sdk

# Install user
RUN useradd -rm -d /home/ppid-tool -s /bin/bash -g root -G sudo -u 1010 ppid-tool
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN echo 'ppid-tool:ppid-tool' | chpasswd
USER ppid-tool
WORKDIR /home/ppid-tool

# Install SGX Dev tools
USER root
RUN apt-get update && apt-get install -y \
    gnupg \
    wget

RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' > /etc/apt/sources.list.d/intel-sgx.list
RUN wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
RUN apt-get update

# App build time dependencies
RUN apt-get install -y build-essential

WORKDIR /opt/intel
RUN wget https://download.01.org/intel-sgx/sgx-linux/2.22/distro/ubuntu22.04-server/sgx_linux_x64_sdk_2.22.100.3.bin
RUN chmod +x sgx_linux_x64_sdk_2.22.100.3.bin
RUN echo 'yes' | ./sgx_linux_x64_sdk_2.22.100.3.bin

# Setup aesmd service in container
USER root
RUN bash -c 'mkdir /var/run/aesmd'
RUN bash -c 'chown -c ppid-tool /var/run/aesmd'

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
