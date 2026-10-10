// SPDX-License-Identifier: MIT OR Apache-2.0
use logos_lez_v03::{Node, deployment};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        return Err(
            "Usage: lez-v03-deployment RPC PROGRAM_ACCOUNT EXPECTED_IMAGE_HEX (read-only)".into(),
        );
    }
    let bytes: [u8; 32] = hex::decode(&args[3])?
        .try_into()
        .map_err(|_| "Expected 32-byte image ID")?;
    let words =
        std::array::from_fn(|i| u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap()));
    let observed = deployment::inspect(&Node::new(&args[1])?, args[2].parse()?, words)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "deployment":observed,"endpoint":args[1],"upstream_revision":logos_lez_v03::UPSTREAM_REVISION,
            "scope":"Node-observed loader state with recomputed image ID and unchanged header on re-read. No historical deployer identity, source rebuild, independent finality or permanent mutable-program guarantee."
        }))?
    );
    Ok(())
}
