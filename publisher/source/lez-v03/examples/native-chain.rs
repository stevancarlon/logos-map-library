// SPDX-License-Identifier: MIT OR Apache-2.0
//! Synthetic local-only integration fixture. Never accepts a public sequencer.
use lee_v03::{PrivateKey, PublicKey};
use logos_lez_v03::{
    AccountId, Node, UPSTREAM_REVISION,
    outbox::{Outbox, State},
    transfer::{NativeReader, NativeTransfer, Wallet},
};
use logos_wallet_policy::{Grant, Scope, principal::Principal};
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
fn account(key: &PrivateKey) -> AccountId {
    AccountId::from_bytes(*lee_v03::AccountId::from(&PublicKey::new_from_private_key(key)).value())
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let key = PrivateKey::try_new([1; 32])?;
    let from = account(&key);
    if args.get(1).map(String::as_str) == Some("fixture-account") {
        println!("{from}");
        return Ok(());
    }
    if args.len() != 3 {
        return Err("Usage: native-chain LOOPBACK_RPC NEW_OUTBOX_PATH".into());
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
    let programs = node.program_ids()?;
    let token_account =
        AccountId::from_bytes(*lee_v03::AccountId::from_builtin_program_name(b"token").value());
    let token_deployment = logos_lez_v03::deployment::inspect(
        &node,
        token_account,
        *programs.get("token").ok_or("Missing token image ID")?,
    )?;
    let wallet = Wallet::new(Node::new(endpoint)?, endpoint)?;
    let to = account(&PrivateKey::try_new([2; 32])?);
    let before = node.native_view(from)?;
    let recipient_before = node.native_view(to)?;
    let transfer = NativeTransfer {
        from,
        to,
        amount: 1234,
        gas_limit: 50_000,
        tip: 7,
        max_fee: 1_000_000,
    };
    let principal = Principal::LocalCli;
    let request_id = "03030303030303030303030303030303";
    let password = b"disposable v03 native chain fixture";
    let path = Path::new(&args[2]);
    let mut outbox = Outbox::create(path, password)?;
    assert_eq!(
        outbox.owner_import_public(zeroize::Zeroizing::new([1; 32]), "Synthetic v0.3 sender")?,
        from
    );
    outbox.owner_set_grant(
        &principal,
        Some(Grant {
            accounts: [from.bytes()].into(),
            scopes: [Scope::Accounts, Scope::Transactions].into(),
        }),
    )?;
    // Reopen before approval to exercise restored keys and permissions.
    drop(outbox);
    let mut outbox = Outbox::open(path, password)?;
    assert_eq!(outbox.accounts_for(&principal)?, vec![from]);
    let prepared = outbox.prepare_native(&principal, &wallet, transfer, now())?;
    assert!(
        outbox
            .execute_native(&principal, request_id, &wallet, &node, &prepared, now())
            .is_err()
    );
    outbox.owner_decide(prepared.prompt().id, true, now())?;
    let acknowledged =
        outbox.execute_native(&principal, request_id, &wallet, &node, &prepared, now())?;
    assert_eq!(acknowledged.state, State::Submitted);
    assert!(
        outbox
            .execute_native(&principal, request_id, &wallet, &node, &prepared, now())
            .is_err()
    );
    drop(outbox);
    let mut outbox = Outbox::open(path, password)?;
    assert_eq!(outbox.status(&principal, request_id)?, acknowledged);
    assert_eq!(outbox.owner_accounts()?[0].account, from);
    assert!(
        outbox
            .execute_native(&principal, request_id, &wallet, &node, &prepared, now())
            .is_err()
    );
    let started = std::time::Instant::now();
    let included = loop {
        let status = outbox.reconcile(&Principal::LocalCli, request_id, &node, now())?;
        if status.state == State::IncludedBySequencer {
            break status;
        }
        if started.elapsed() > Duration::from_secs(120) {
            return Err("Saved v0.3 transaction was not observed included".into());
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let after = node.native_view(from)?;
    let recipient_after = node.native_view(to)?;
    assert_eq!(after.nonce, before.nonce + 1);
    assert_eq!(recipient_after.nonce, recipient_before.nonce);
    assert_eq!(
        recipient_after.native_balance()?,
        recipient_before
            .native_balance()?
            .checked_add(transfer.amount)
            .ok_or("recipient overflow")?
    );
    let debit = before
        .native_balance()?
        .checked_sub(after.native_balance()?)
        .ok_or("sender balance increased")?;
    let fee = debit
        .checked_sub(transfer.amount)
        .ok_or("sender debit below transfer amount")?;
    assert!(fee > 0 && fee <= transfer.max_fee);
    drop(outbox);
    let reopened = Outbox::open(path, password)?;
    assert_eq!(reopened.status(&Principal::LocalCli, request_id)?, included);
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "result":"passed","adapter_revision":UPSTREAM_REVISION,"transaction":included,"from":from,"to":to,
            "amount":transfer.amount.to_string(),"observed_fee_debit":fee.to_string(),"approved_maximum_fee":transfer.max_fee.to_string(),
            "sender_before":before.native_balance()?.to_string(),"sender_after":after.native_balance()?.to_string(),
            "recipient_before":recipient_before.native_balance()?.to_string(),"recipient_after":recipient_after.native_balance()?.to_string(),
            "sender_nonce_advanced_once":true,"recipient_nonce_unchanged":true,"approval_one_use":true,"stored_key_signing":true,"keys_and_permissions_survived_restart":true,"outbox_restart_preserved_hash_and_status":true,
            "program_ids":programs,"token_deployment":token_deployment,"scope":"Synthetic local v0.3 standalone sequencer transfer with observed fee debit and loader image reconstruction. No public testnet transaction, independent finality, Basecamp integration or adoption."
        }))?
    );
    Ok(())
}
