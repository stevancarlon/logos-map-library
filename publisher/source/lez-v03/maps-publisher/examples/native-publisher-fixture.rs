// SPDX-License-Identifier: MIT OR Apache-2.0
//! Creates a NEW disposable fixture directory only; never use this public test key elsewhere.
use logos_maps_v03_publisher::Publisher;
use logos_wallet_policy::vault;
use std::path::Path;
use zeroize::Zeroizing;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        return Err("Usage: native-publisher-fixture NEW_FIXTURE_DIRECTORY".into());
    }
    let directory = Path::new(&args[1]);
    std::fs::create_dir(directory)?;
    let mut payload = Zeroizing::new(Vec::from(b"REGKEY01".as_slice()));
    payload.extend_from_slice(&[1; 32]);
    vault::create_file(
        &directory.join("key.vault"),
        b"maps-native-fixture",
        &payload,
    )?;
    Publisher::create(&directory.join("outbox.sqlite"), b"maps-native-fixture")?;
    Ok(())
}
