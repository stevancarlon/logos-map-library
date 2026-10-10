// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fixed funding for a disposable, loopback-only Basecamp integration fixture.
use logos_registry_sdk::{AccountReader, HttpNode};
use logos_wallet_lez::{
    NativeTransfer, NativeWallet,
    token::{FungibleTransfer, NftTransfer},
};
use logos_wallet_policy::{AppId, Grant, Policy, Scope};
use serde_json::json;
use std::{collections::BTreeSet, time::Duration};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if !(3..=4).contains(&args.len()) {
        return Err("Usage: fund-owner-fixture http://127.0.0.1:PORT RECIPIENT [fungible|nft] or ENDPOINT describe-tokens".into());
    }
    let port = args[1]
        .strip_prefix("http://127.0.0.1:")
        .ok_or("Only a disposable loopback sequencer is accepted")?
        .parse::<u16>()?;
    if port == 0 || args[1] != format!("http://127.0.0.1:{port}") {
        return Err("Invalid loopback endpoint".into());
    }
    let fixture_id = |byte| -> Result<lee::AccountId, Box<dyn std::error::Error>> {
        Ok(lee::AccountId::from(&lee::PublicKey::new_from_private_key(
            &lee::PrivateKey::try_new([byte; 32])?,
        )))
    };
    if args[2] == "describe-tokens" && args.len() == 3 {
        println!(
            "{}",
            json!([
                {"kind":"fungible","definition":fixture_id(6)?},
                {"kind":"nft","definition":fixture_id(21)?}
            ])
        );
        return Ok(());
    }
    let mode = args.get(3).map(String::as_str).unwrap_or("native");
    let (key_byte, definition_byte) = match mode {
        "native" => (1, 1),
        "fungible" => (8, 6),
        "nft" => (25, 21),
        _ => return Err("Unknown fixture asset".into()),
    };
    let recipient: lee::AccountId = args[2].parse()?;
    let key = lee::PrivateKey::try_new([key_byte; 32])?;
    let definition = fixture_id(definition_byte)?;
    let sender = lee::AccountId::from(&lee::PublicKey::new_from_private_key(&key));
    let node = HttpNode::new(&args[1])?;
    let before = node.account(recipient)?.balance;
    let app = AppId("disposable.owner.funding.fixture".into());
    let mut policy = Policy::default();
    policy.set_grant(
        app.clone(),
        Grant {
            accounts: BTreeSet::from([*sender.value()]),
            scopes: BTreeSet::from([Scope::Transactions]),
        },
    )?;
    let wallet = NativeWallet::connect(&args[1])?;
    let prepared = match mode {
        "fungible" => wallet.prepare_fungible(
            &mut policy,
            &app,
            FungibleTransfer {
                from: *sender.value(),
                to: *recipient.value(),
                asset: *definition.value(),
                amount: 25,
            },
            100,
        )?,
        "nft" => wallet.prepare_nft(
            &mut policy,
            &app,
            NftTransfer {
                from: *sender.value(),
                to: *recipient.value(),
                collection: *definition.value(),
            },
            100,
        )?,
        _ => wallet.prepare_native(
            &mut policy,
            &app,
            NativeTransfer {
                from: *sender.value(),
                to: *recipient.value(),
                amount: 25,
            },
            100,
        )?,
    };
    // Explicit fixture funding decision, never a real user's approval.
    policy.decide(prepared.prompt().id, true, 101)?;
    let hash = wallet.execute(&mut policy, &app, &prepared, &key, 102)?;
    for _ in 0..120 {
        if node.confirmed(hash)? {
            let after = node.account(recipient)?.balance;
            if mode == "native" && after != before.checked_add(25).ok_or("Balance overflow")? {
                return Err("Unexpected funded balance".into());
            }
            let holding = if mode != "native" {
                let state = token_core::TokenHolding::try_from(&node.account(recipient)?.data)?;
                let expected = if mode == "fungible" {
                    token_core::TokenHolding::Fungible {
                        definition_id: definition,
                        balance: 25,
                    }
                } else {
                    token_core::TokenHolding::NftPrintedCopy {
                        definition_id: definition,
                        owned: true,
                    }
                };
                if state != expected {
                    return Err("Unexpected funded holding".into());
                }
                Some(logos_wallet_lez::token::HoldingView::from(state))
            } else {
                None
            };
            println!(
                "{}",
                json!({"hash":hash,"recipient":args[2],"asset":mode,"holding":holding,"before":before.to_string(),"after":after.to_string(),"amount":if mode == "nft" {"1"} else {"25"},"included_by_sequencer":true})
            );
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err("Fixture funding inclusion timed out; do not blindly replay".into())
}
