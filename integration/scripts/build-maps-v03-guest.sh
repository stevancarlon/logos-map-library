#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."
: "${RISC0_RUSTC:?Set the pinned RISC Zero 1.97.0 rustc path}"
maps_guest_target="${MAPS_V03_GUEST_TARGET:-$PWD/lez-v03/maps-guest/target}"
# Official risc0-build text placement and atomic lowering for the single-threaded guest.
RUSTC="$RISC0_RUSTC" CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$maps_guest_target" \
  CARGO_TARGET_RISCV32IM_RISC0_ZKVM_ELF_RUSTFLAGS='--cfg getrandom_backend="unsupported" -C passes=lower-atomic -C panic=abort -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings' \
  cargo build --manifest-path lez-v03/maps-guest/Cargo.toml --locked \
  --target riscv32im-risc0-zkvm-elf --release -j 4
mkdir -p artifacts/maps-v03
cp "$maps_guest_target/riscv32im-risc0-zkvm-elf/release/logos-maps-v03-guest" \
  artifacts/maps-v03/program.elf
