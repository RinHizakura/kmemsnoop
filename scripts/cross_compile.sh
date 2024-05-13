#!/usr/bin/env bash

C_PATH=$HOME/x-tools/aarch64-unknown-linux-gnu/bin

export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$C_PATH/aarch64-unknown-linux-gnu-gcc"
cargo build --target aarch64-unknown-linux-gnu
