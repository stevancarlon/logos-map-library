// SPDX-License-Identifier: MIT OR Apache-2.0
//! Disposable local registry metadata for actual Basecamp review checks.
use logos_registry_sdk::{AccountReader, HttpNode, publisher::Write};
use logos_wallet_lez::keyring::Keyring;
use serde_json::json;
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        return Err("RPC REGISTRY seed|update|state WALLET_PATH required".into());
    }
    let port = args[1]
        .strip_prefix("http://127.0.0.1:")
        .ok_or("Loopback fixture only")?
        .parse::<u16>()?;
    if port == 0 || args[1] != format!("http://127.0.0.1:{port}") {
        return Err("Invalid fixture endpoint".into());
    }
    let node = HttpNode::new(&args[1])?;
    let registry = logos_registry_sdk::parse_program(&args[2])?;
    let key = lee::PrivateKey::try_new([1; 32])?;
    let author = lee::AccountId::from(&lee::PublicKey::new_from_private_key(&key));
    let to = lee::AccountId::from(&lee::PublicKey::new_from_private_key(
        &lee::PrivateKey::try_new([2; 32])?,
    ));
    let target = logos_registry_sdk::program_bytes(&programs::authenticated_transfer().id());
    let metadata = logos_prize_registry::Metadata {
        name: "Native source review fixture".into(),
        version: if args[3] == "update" { "2" } else { "1" }.into(),
        author: "Disposable fixture".into(),
        description: "Synthetic metadata; no rebuild or adoption claim".into(),
        tags: vec![],
        idl_cid: "bafyFixtureIdl".into(),
        source_cid: "bafyFixtureSource".into(),
        source_commit: "a".repeat(40),
        build_config_cid: "bafyFixtureRecipe".into(),
    };
    let write = match args[3].as_str() {
        "seed" => {
            let path = Path::new(&args[4]);
            std::fs::create_dir_all(path.parent().ok_or("Wallet parent missing")?)?;
            let mut ring = Keyring::create(path, b"disposable source review password")?;
            ring.import_public("Source review fixture", &[1; 32])?;
            Some(Write::Register {
                target,
                page: 0,
                submitted_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)?
                    .as_millis()
                    .try_into()?,
                metadata,
            })
        }
        "update" => Some(Write::Update {
            target,
            expected_revision: 0,
            metadata,
        }),
        "state" => None,
        _ => return Err("Unknown fixture action".into()),
    };
    let mut transaction = None;
    if let Some(write) = write {
        let signed = node.sign_write(registry, &key, &write)?;
        let hash = node.submit(&signed)?;
        let mut included = false;
        for _ in 0..120 {
            if node.confirmed(hash)? {
                included = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        if !included {
            return Err("Fixture transaction not included".into());
        }
        transaction = Some(hash);
    }
    let state = node.account(author)?;
    println!(
        "{}",
        json!({"registry":args[2],"program":target.iter().map(|b|format!("{b:02x}")).collect::<String>(),"registrant":author,"from":author,"to":to,"transaction":transaction,"balance":state.balance.to_string(),"nonce":state.nonce.0.to_string()})
    );
    Ok(())
}
