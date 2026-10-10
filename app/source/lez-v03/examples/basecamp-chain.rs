// SPDX-License-Identifier: MIT OR Apache-2.0
//! Synthetic local v0.3 chain + actual Basecamp approval/signing fixture.
use lee_v03::{PrivateKey, PublicKey};
use logos_lez_v03::{AccountId, Node, UPSTREAM_REVISION, outbox::Outbox, transfer::NativeReader};
use std::{
    path::Path,
    process::{Command, Stdio},
};
fn account(n: u8) -> Result<AccountId, Box<dyn std::error::Error>> {
    let key = PrivateKey::try_new([n; 32])?;
    Ok(AccountId::from_bytes(
        *lee_v03::AccountId::from(&PublicKey::new_from_private_key(&key)).value(),
    ))
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let from = account(1)?;
    if args.get(1).map(String::as_str) == Some("fixture-account") {
        println!("{from}");
        return Ok(());
    }
    let owner_ui = args.get(4).map(String::as_str) == Some("--owner-ui");
    let production_ui = owner_ui || args.get(4).map(String::as_str) == Some("--production-ui");
    if args.len() != 4 && !(args.len() == 5 && production_ui) {
        return Err(
            "Usage: basecamp-chain LOOPBACK_RPC NEW_FIXTURE_WALLET BASECAMP_APPIMAGE".into(),
        );
    }
    let endpoint = &args[1];
    let uri: ureq::http::Uri = endpoint.parse()?;
    if uri.scheme_str() != Some("http")
        || uri.host() != Some("127.0.0.1")
        || uri.port_u16().is_none()
    {
        return Err("Only disposable loopback sequencers accepted".into());
    }
    let node = Node::new(endpoint)?;
    let to = account(2)?;
    let before = node.native_view(from)?;
    let recipient_before = node.native_view(to)?;
    let path = Path::new(&args[2]);
    let mut store = Outbox::create(path, b"synthetic v03 Basecamp password")?;
    assert_eq!(
        store.owner_import_public(zeroize::Zeroizing::new([1; 32]), "Owner private label")?,
        from
    );
    drop(store);
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut command = Command::new("python3");
    if owner_ui {
        let context = path.with_extension("owner-context.json");
        std::fs::write(
            &context,
            serde_json::to_vec(
                &serde_json::json!({"transfers":[{"kind":"native","from":from,"to":to,"amount":"1234","gas_limit":"50000","tip":"7","max_fee":"1000000","native_before":before.native_balance()?.to_string()}]}),
            )?,
        )?;
        command
            .arg(root.join("scripts/test-basecamp-v03-owner.py"))
            .args([
                "--basecamp",
                &args[3],
                "--rpc",
                endpoint,
                "--seed-wallet",
                &args[2],
                "--context",
            ])
            .arg(context);
    } else {
        command
            .arg(root.join("scripts/test-basecamp-v03-access.py"))
            .args([
                "--basecamp",
                &args[3],
                "--rpc",
                endpoint,
                "--seed-wallet",
                &args[2],
                "--recipient",
                &to.to_string(),
            ]);
        if production_ui {
            command.arg("--production-ui");
        }
    }
    let child = command
        .env("TMPDIR", root.join(".tmp"))
        .stderr(Stdio::inherit())
        .output()?;
    eprint!("{}", String::from_utf8_lossy(&child.stdout));
    if !child.status.success() {
        return Err("Actual Basecamp transaction fixture failed".into());
    }
    let evidence: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join(if owner_ui {
            "evidence/basecamp-v03-owner-native.json"
        } else if production_ui {
            "evidence/basecamp-v03-ui-transaction.json"
        } else {
            "evidence/basecamp-v03-transaction.json"
        }))?)?;
    assert_eq!(evidence["result"], "passed");
    let after = node.native_view(from)?;
    let recipient_after = node.native_view(to)?;
    assert_eq!(after.nonce, before.nonce + 1);
    assert_eq!(recipient_after.nonce, recipient_before.nonce);
    assert_eq!(
        recipient_after.native_balance()?,
        recipient_before.native_balance()? + 1234
    );
    let fee = before
        .native_balance()?
        .checked_sub(after.native_balance()?)
        .and_then(|d| d.checked_sub(1234))
        .ok_or("invalid sender debit")?;
    assert!(fee > 0 && fee <= 1_000_000);
    if owner_ui {
        assert_eq!(
            evidence["after"][0]["inventory"]["native_balance"],
            after.native_balance()?.to_string()
        );
    }
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "result":"passed","adapter_revision":UPSTREAM_REVISION,"basecamp":evidence,
            "from":from,"to":to,"amount":"1234","observed_fee_debit":fee.to_string(),"approved_maximum_fee":"1000000",
            "sender_before":before.native_balance()?.to_string(),"sender_after":after.native_balance()?.to_string(),
            "recipient_before":recipient_before.native_balance()?.to_string(),"recipient_after":recipient_after.native_balance()?.to_string(),
            "sender_nonce_advanced_once":true,"recipient_nonce_unchanged":true,
            "scope":if owner_ui {"Actual Basecamp production QML owner send form, balance read, separate rejection/approval, local native transfer, observed fee and restart without persisted app grants. No private proofs, public-testnet writes, release or adoption."} else if production_ui {"Actual Basecamp production v0.3 QML account/access/review/activity paths with synthetic automated consent, native signing, local sequencer effects and restart. Complete owner send-form/token UI verification, private proofs, public-testnet writes and adoption remain incomplete."} else {"Actual Basecamp host-to-v0.3 wallet request, fixture owner rejection then separate approval, signing and actual local sequencer effects. No production QML interface, public-testnet writes, private proofs or adoption."}
        }))?
    );
    Ok(())
}
