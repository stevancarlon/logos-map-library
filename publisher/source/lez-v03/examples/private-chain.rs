// SPDX-License-Identifier: MIT OR Apache-2.0
//! Genuine local v0.3 private native roundtrip; synthetic encrypted fixture only.
use lee_v03::{PrivateKey, PublicKey};
use logos_lez_v03::{
    AccountId, Node, UPSTREAM_REVISION,
    outbox::Outbox,
    shielded::{Direction, NativeOperation, PrivateIdentity},
    transfer::NativeReader,
};
use serde_json::json;
use std::{
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn id(key: u8) -> AccountId {
    AccountId::from_bytes(
        *lee_v03::AccountId::from(&PublicKey::new_from_private_key(
            &PrivateKey::try_new([key; 32]).unwrap(),
        ))
        .value(),
    )
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("fixture-account") {
        println!("{}", id(1));
        return Ok(());
    }
    if args.len() != 3 {
        return Err("Usage: private-chain LOOPBACK_RPC NEW_WALLET".into());
    }
    let uri: ureq::http::Uri = args[1].parse()?;
    if uri.scheme_str() != Some("http")
        || uri.host() != Some("127.0.0.1")
        || uri.port_u16().is_none()
    {
        return Err("Only disposable loopback sequencers accepted".into());
    }
    let node = Node::new(&args[1])?;
    let path = Path::new(&args[2]);
    let password = b"synthetic v03 private fixture password";
    let mut store = Outbox::create(path, password)?;
    assert_eq!(
        store.owner_import_public(
            zeroize::Zeroizing::new([1; 32]),
            "Synthetic public funding account"
        )?,
        id(1)
    );
    let private = store.owner_import_private(
        PrivateIdentity::from_seed(zeroize::Zeroizing::new([71; 32]), [72; 32]),
        "Synthetic private account",
    )?;
    drop(store);
    let mut store = Outbox::open(path, password)?;
    assert_eq!(store.owner_private_accounts()?[0]["initialized"], false);
    let public_before = node.native_view(id(1))?;
    let recipient_before = node.native_view(id(2))?;
    let mut outcomes = Vec::new();
    for (index, direction, amount, public) in [
        (0, Direction::Deposit, 1234u128, id(1)),
        (1, Direction::Withdrawal, 234u128, id(2)),
    ] {
        let request_id = format!("{:032x}", index + 700);
        let operation = NativeOperation {
            public_account: public,
            direction,
            amount,
        };
        let cancelled = store.owner_prepare_private_native(&node, private, operation, now())?;
        let unchanged = std::fs::read(path)?;
        store.owner_decide(cancelled.prompt().id, false, now())?;
        assert!(
            store
                .owner_execute_private_native(&request_id, &node, &cancelled, now())
                .is_err()
        );
        assert_eq!(std::fs::read(path)?, unchanged);
        let prepared = store.owner_prepare_private_native(&node, private, operation, now())?;
        store.owner_decide(prepared.prompt().id, true, now())?;
        eprintln!("Starting genuine v0.3 {direction:?} proof; request {request_id}");
        let start = Instant::now();
        let submitted = store.owner_execute_private_native(&request_id, &node, &prepared, now())?;
        eprintln!(
            "Genuine v0.3 {direction:?} proof/submission finished in {:?}",
            start.elapsed()
        );
        assert_eq!(submitted["transaction"]["state"], "submitted");
        assert_eq!(submitted["opening_confirmed"], false);
        assert!(
            store
                .owner_execute_private_native(&request_id, &node, &prepared, now())
                .is_err()
        );
        drop(store);
        store = Outbox::open(path, password)?;
        assert_eq!(store.owner_private_status(&request_id)?, submitted);
        let deadline = Instant::now() + Duration::from_secs(180);
        let confirmed = loop {
            let status = store.owner_reconcile_private(&request_id, &node, now())?;
            if status["opening_confirmed"] == true {
                break status;
            }
            if Instant::now() > deadline {
                return Err("Private commitment did not settle".into());
            }
            std::thread::sleep(Duration::from_secs(1));
        };
        let accounts = store.owner_private_accounts()?;
        assert_eq!(
            accounts[0]["native_balance"],
            if index == 0 { "1234" } else { "1000" }
        );
        assert!(accounts[0]["pending"].is_null());
        outcomes.push(confirmed);
        drop(store);
        store = Outbox::open(path, password)?;
        assert_eq!(store.owner_private_accounts()?, accounts);
    }
    let public_after = node.native_view(id(1))?;
    let recipient_after = node.native_view(id(2))?;
    assert_eq!(
        public_before.native_balance()? - public_after.native_balance()?,
        1234
    );
    assert_eq!(public_after.nonce, public_before.nonce + 1);
    assert_eq!(
        recipient_after.native_balance()? - recipient_before.native_balance()?,
        234
    );
    assert_eq!(recipient_after.nonce, recipient_before.nonce);
    let before = store.owner_private_accounts()?;
    store.owner_reconcile_private("000000000000000000000000000002bc", &node, now())?;
    assert_eq!(
        store.owner_private_accounts()?,
        before,
        "Historical reconciliation must not roll back a newer opening"
    );
    let new_password = b"rotated synthetic private fixture password";
    store.owner_rotate_password(password, new_password)?;
    drop(store);
    assert!(Outbox::open(path, password).is_err());
    let store = Outbox::open(path, new_password)?;
    assert_eq!(store.owner_private_accounts()?, before);
    assert_eq!(store.owner_private_activity()?.len(), 2);
    println!(
        "{}",
        serde_json::to_string(
            &json!({"result":"passed","adapter_revision":UPSTREAM_REVISION,"private_account":private,"private_native_balance":"1000","public_debit":"1234","public_recipient_credit":"234","observed_fee_debit":"0","public_sender_nonce_advanced_once":true,"public_recipient_nonce_unchanged":true,"outcomes":outcomes,"restart_and_rotation":true,"historical_reconciliation_preserves_newer_opening":true,"scope":"Genuine local v0.3 private native deposit/init and withdrawal proofs, pinned receipt verification, exact saved wire/commitment reconciliation, encrypted restart and password rotation. Synthetic accounts; no token/private-pair/membership proof, Basecamp private UI, public-testnet writes, release or adoption."})
        )?
    );
    Ok(())
}
