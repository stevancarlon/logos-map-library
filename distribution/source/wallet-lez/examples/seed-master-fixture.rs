// SPDX-License-Identifier: MIT OR Apache-2.0
//! Mints a disposable master and seeds a NEW native UI fixture wallet with its key.
use logos_registry_sdk::{AccountReader, HttpNode};
use logos_wallet_lez::keyring::Keyring;
use serde_json::json;
use std::path::Path;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err("Usage: seed-master-fixture http://127.0.0.1:PORT NEW_WALLET_SQLITE".into());
    }
    let port = args[1]
        .strip_prefix("http://127.0.0.1:")
        .ok_or("Loopback fixture required")?
        .parse::<u16>()?;
    if port == 0 || args[1] != format!("http://127.0.0.1:{port}") {
        return Err("Invalid loopback endpoint".into());
    }
    let path = Path::new(&args[2]);
    if !path.is_absolute() || path.exists() {
        return Err("Only a new absolute wallet path is accepted".into());
    }
    let node = HttpNode::new(&args[1])?;
    let keys = [
        lee::PrivateKey::try_new([81; 32])?,
        lee::PrivateKey::try_new([82; 32])?,
        lee::PrivateKey::try_new([83; 32])?,
    ];
    let ids = keys
        .iter()
        .map(|key| lee::AccountId::from(&lee::PublicKey::new_from_private_key(key)))
        .collect::<Vec<_>>();
    let mut nonces = Vec::new();
    for id in &ids {
        let state = node.account(*id)?;
        if state != lee::Account::default() {
            return Err("Master fixture setup accounts are not fresh".into());
        }
        nonces.push(state.nonce);
    }
    let message = lee::public_transaction::Message::try_new(
        programs::token().id(),
        ids.clone(),
        nonces,
        token_core::Instruction::NewDefinitionWithMetadata {
            new_definition: token_core::NewTokenDefinition::NonFungible {
                name: "Disposable master transfer fixture".into(),
                printable_supply: 7,
            },
            metadata: Box::new(token_core::NewTokenMetadata {
                standard: token_core::MetadataStandard::Simple,
                uri: "storage://unavailablefixture".into(),
                creators: "local fixture".into(),
            }),
        },
    )?;
    let witness = lee::public_transaction::WitnessSet::for_message(
        &message,
        &keys.iter().collect::<Vec<_>>(),
    );
    let transaction =
        common::transaction::LeeTransaction::Public(lee::PublicTransaction::new(message, witness));
    let setup_hash = transaction.hash();
    if node.submit(&transaction)? != setup_hash {
        return Err("Setup returned a mismatching hash".into());
    }
    let mut included = false;
    for _ in 0..120 {
        if node.confirmed(setup_hash)? {
            included = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    if !included {
        return Err("Fixture mint inclusion timed out; do not replay blindly".into());
    }
    let source = ids[1];
    let account = node.account(source)?;
    if account.program_owner != programs::token().id() {
        return Err("Fixture master missing".into());
    }
    let token_core::TokenHolding::NftMaster {
        definition_id,
        print_balance,
    } = token_core::TokenHolding::try_from(&account.data)?
    else {
        return Err("Expected fixture master".into());
    };
    if print_balance <= 1 {
        return Err("Fixture master must have remaining print rights".into());
    }
    let mut ring = Keyring::create(path, b"disposable native wallet fixture password")?;
    assert_eq!(
        ring.import_public("Disposable master NFT fixture", &[82; 32])?,
        source
    );
    let destination = ring.generate_public("Fresh master recipient fixture")?;
    if node.account(destination)? != lee::Account::default() {
        return Err("Recipient must be fresh".into());
    }
    println!(
        "{}",
        json!({"endpoint":args[1],"setup_hash":setup_hash,"source":source,"destination":destination,"definition":definition_id,"print_balance":print_balance.to_string(),"remaining_prints":(print_balance-1).to_string()})
    );
    Ok(())
}
