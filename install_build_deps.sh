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

apt_get_with_retry() {
    local -r retries="${APT_GET_RETRIES:-3}"
    local -r timeout_seconds="${APT_GET_TIMEOUT_SECONDS:-10}"

    run_as_root apt-get \
        -o Acquire::Retries="$retries" \
        -o Acquire::http::Timeout="$timeout_seconds" \
        -o Acquire::https::Timeout="$timeout_seconds" \
        -o DPkg::Lock::Timeout="$timeout_seconds" \
        "$@"
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
apt_get_with_retry update -y
apt_get_with_retry install -y gpg

info "Adding Intel SGX package repository key..."
cat intel-sgx-deb.key | gpg --dearmor | $SUDO tee /usr/share/keyrings/intel-sgx-deb.gpg > /dev/null

info "Adding Intel SGX repository to sources.list.d..."
ARCH=$(dpkg --print-architecture)
echo "deb [arch=$ARCH signed-by=/usr/share/keyrings/intel-sgx-deb.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main" | $SUDO tee /etc/apt/sources.list.d/intel-sgx-deb.list > /dev/null

info "Updating package lists..."
apt_get_with_retry update -y

info "Installing build dependencies: faketime protobuf-compiler libsgx-dcap-ql-dev clang-18 musl-tools gcc-multilib"
apt_get_with_retry install -y faketime protobuf-compiler libsgx-dcap-ql-dev clang-18 musl-tools gcc-multilib

info "All dependencies installed successfully."
