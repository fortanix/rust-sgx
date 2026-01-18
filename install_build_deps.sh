#!/bin/bash
set -euo pipefail

# Functions
error() {
    echo "Error: $*" >&2
    exit 1
}

info() {
    echo "[INFO] $*"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || error "Required command '$1' not found. Please install it."
}

run_as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

# Check for required commands
for cmd in tee dpkg apt-get; do
    require_command "$cmd"
done

# Check for permission to run apt-get update/install
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif command -v sudo >/dev/null 2>&1; then
    if ! sudo -n true 2>/dev/null; then
        error "This script requires permission to run 'apt-get update/install'. Please run as root or ensure you have passwordless sudo access."
    fi
    SUDO="sudo"
else
    error "This script requires root or sudo privileges to run 'apt-get update/install'."
fi

export DEBIAN_FRONTEND=noninteractive

info "Updating package lists and installing gpg..."
$SUDO apt-get update -y
$SUDO apt-get install -y gpg

info "Adding Intel SGX package repository key..."
cat intel-sgx-deb.key | gpg --dearmor | $SUDO tee /usr/share/keyrings/intel-sgx-deb.gpg > /dev/null

info "Adding Intel SGX repository to sources.list.d..."
ARCH=$(dpkg --print-architecture)
echo "deb [arch=$ARCH signed-by=/usr/share/keyrings/intel-sgx-deb.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main" | $SUDO tee /etc/apt/sources.list.d/intel-sgx-deb.list > /dev/null

info "Updating package lists..."
$SUDO apt-get update -y

info "Installing build dependencies: faketime protobuf-compiler libsgx-dcap-ql-dev clang-18 musl-tools gcc-multilib libtdx-attest-dev"
$SUDO apt-get install -y faketime protobuf-compiler libsgx-dcap-ql-dev clang-18 musl-tools gcc-multilib libtdx-attest-dev

info "All dependencies installed successfully."
