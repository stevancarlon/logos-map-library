// SPDX-License-Identifier: MIT OR Apache-2.0
//! Wrap a validated raw guest ELF for the pinned official wallet deployment path.
use anyhow::{ensure, Result};
use std::{fs, io::Write, path::Path};

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 3,
        "Usage: maps-deployment-artifact RAW_ELF NEW_PROGRAM_BIN"
    );
    let elf = fs::read(&args[1])?;
    let binary = risc0_binfmt::ProgramBinary::new(&elf, risc0_zkos_v1compat::V1COMPAT_ELF);
    let image_id: [u32; 8] = binary.compute_image_id()?.into();
    let encoded = binary.encode();
    // Apply the same format/kernel conditions as the official wallet's loader.
    let decoded = risc0_binfmt::ProgramBinary::decode(&encoded)?;
    ensure!(decoded.user_elf == elf.as_slice());
    ensure!(decoded.kernel_elf == risc0_zkos_v1compat::V1COMPAT_ELF);
    let segments = decoded
        .user_elf
        .len()
        .div_ceil(program_loader_v03::MAX_SEGMENT_DATA_LEN);
    ensure!(segments > 0 && segments <= program_loader_v03::MAX_PROGRAM_SEGMENTS);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(Path::new(&args[2]))?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    println!(
        "{}",
        serde_json::json!({
            "format":"risc0-binfmt ProgramBinary", "kernel":"risc0-zkos-v1compat 2.2.2",
            "user_elf_bytes":elf.len(), "container_bytes":encoded.len(), "image_id":image_id,
            "segment_accounts_required":segments, "segment_bytes_limit":program_loader_v03::MAX_SEGMENT_DATA_LEN,
            "public_program_account":null, "deployment_status":"not_deployed_to_official_testnet"
        })
    );
    Ok(())
}
