#!/usr/bin/env bash
set -e

apt update
apt install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libclang-dev \
    libzstd-dev \
    git \
    curl

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

rustup default stable
rustup target add x86_64-unknown-linux-musl

cargo build -p amadeusd --bin amadeusd --release

gramine-sgx-gen-private-key
gramine-manifest amadeusd.manifest.template amadeusd.manifest
gramine-sgx-sign --manifest amadeusd.manifest --output amadeusd.manifest.sgx

#gramine-sgx amadeusd
