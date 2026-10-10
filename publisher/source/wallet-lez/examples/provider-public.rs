// SPDX-License-Identifier: MIT OR Apache-2.0
//! Disposable loopback-only provider-domain integration. No GUI/adoption claim.
use logos_registry_sdk::{
    AccountReader, HttpNode,
    publisher::Write,
    verification::{ReviewConfig, SourceState},
};
use logos_wallet_lez::{
    keyring::{Keyring, public_outbox::SubmissionState},
    provider::{Provider, transactions::TransactionState},
};
use logos_wallet_policy::{Grant, Scope, principal::Principal};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn id(key: u8) -> Result<lee::AccountId> {
    Ok(lee::AccountId::from(&lee::PublicKey::new_from_private_key(
        &lee::PrivateKey::try_new([key; 32])?,
    )))
}
fn perform(
    provider: &mut Provider,
    app: &Principal,
    proposal: Value,
    node: &HttpNode,
) -> Result<(String, common::HashType)> {
    let request = provider.dispatch(
        app,
        &json!({"method":"propose_transaction","proposal":proposal}).to_string(),
        now(),
    )?;
    let request_id = request["id"]
        .as_str()
        .ok_or("Missing request id")?
        .to_owned();
    assert!(matches!(
        provider.transaction_status(app, &request_id, now())?,
        TransactionState::Pending
    ));
    let prompts = provider.transaction_prompts(now());
    assert!(prompts.iter().any(|prompt| prompt.id == request_id
        && prompt.principal == *app
        && matches!(
            prompt.source_verification.state,
            SourceState::NotChecked
                | SourceState::Registered {
                    local_rebuild: None,
                    ..
                }
        )));
    // Explicit trusted fixture decision: never a dApp-side dispatch command.
    let TransactionState::Submission { submission } =
        provider.decide_configured_transaction(&request_id, true, now())?
    else {
        return Err("Submission missing".into());
    };
    assert_eq!(submission.state, SubmissionState::Submitted);
    assert!(
        provider
            .decide_configured_transaction(&request_id, true, now())
            .is_err()
    );
    for _ in 0..120 {
        if node.confirmed(submission.hash)? {
            let checked_at = now();
            let refreshed = provider.dispatch(
                app,
                &json!({"method":"refresh_transaction","id":request_id}).to_string(),
                checked_at,
            )?;
            assert_eq!(refreshed["submission"]["state"], "included_by_sequencer");
            assert_eq!(refreshed["submission"]["last_checked_at"], checked_at);
            return Ok((request_id, submission.hash));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err("Provider transaction was not included by the local sequencer".into())
}
fn source_review(
    provider: &mut Provider,
    app: &Principal,
    node: &HttpNode,
    registry_hex: &str,
    receipts: std::path::PathBuf,
) -> Result<Value> {
    let registry = logos_registry_sdk::parse_program(registry_hex)?;
    let key = lee::PrivateKey::try_new([1; 32])?;
    let author = id(1)?;
    let target = logos_registry_sdk::program_bytes(&programs::authenticated_transfer().id());
    let mut metadata = logos_prize_registry::Metadata {
        name: "Unverified provider integration fixture".into(),
        version: "1".into(),
        author: "Disposable local fixture".into(),
        description: "No source rebuild, deployment authority, or adoption claim".into(),
        tags: vec![],
        idl_cid: "bafyFixtureIdl".into(),
        source_cid: "bafyFixtureSource".into(),
        source_commit: "a".repeat(40),
        build_config_cid: "bafyFixtureBuild".into(),
    };
    let send = |write| -> Result<common::HashType> {
        let signed = node.sign_write(registry, &key, &write)?;
        let hash = node.submit(&signed)?;
        for _ in 0..120 {
            if node.confirmed(hash)? {
                return Ok(hash);
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err("Registry write did not appear in local sequencer".into())
    };
    let registered = send(Write::Register {
        target,
        page: 0,
        submitted_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .try_into()?,
        metadata: metadata.clone(),
    })?;
    provider.configure_source_review(Some(ReviewConfig::new(
        registry_hex,
        receipts,
        BTreeMap::from([(target, *author.value())]),
    )?));
    let proposed = provider.dispatch(app, &json!({"method":"propose_transaction","proposal":{"kind":"native_transfer","from":author,"to":id(2)?,"amount":"1"}}).to_string(), now())?;
    let request = proposed["id"]
        .as_str()
        .ok_or("Missing source review request")?;
    let prompts = provider.transaction_prompts(now());
    assert_eq!(prompts.len(), 1);
    assert!(matches!(
        prompts[0].source_verification.state,
        SourceState::Registered {
            revision: 0,
            local_rebuild: None,
            ..
        }
    ));
    metadata.version = "2".into();
    let updated = send(Write::Update {
        target,
        expected_revision: 0,
        metadata,
    })?;
    let before = node.account(author)?;
    assert!(matches!(
        provider.decide_configured_transaction(request, true, now()),
        Err(logos_wallet_lez::provider::Error::SourceChanged)
    ));
    assert_eq!(node.account(author)?, before);
    assert!(
        provider
            .decide_configured_transaction(request, true, now())
            .is_err()
    );
    Ok(
        json!({"registration":registered,"update":updated,"changed_registry_review_rejected":true,"rejection_preserved_account_state":true,"registration_not_claimed_as_rebuild":true}),
    )
}
fn main() -> Result<()> {
    let endpoint = std::env::args()
        .nth(1)
        .ok_or("Loopback endpoint required")?;
    let port = endpoint
        .strip_prefix("http://127.0.0.1:")
        .ok_or("Only loopback fixture endpoints are accepted")?;
    port.parse::<u16>()?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("provider.sqlite");
    let password = b"public provider fixture password";
    let mut ring = Keyring::create(&path, password)?;
    let mut accounts = BTreeSet::new();
    for key in [1u8, 7, 25, 28, 29, 30] {
        accounts.insert(
            *ring
                .import_public(&format!("Fixture {key}"), &[key; 32])?
                .value(),
        );
    }
    let app = Principal::Module {
        name: "provider_fixture_app".into(),
        instance: String::new(),
    };
    let other = Principal::Module {
        name: "other_fixture_app".into(),
        instance: String::new(),
    };
    let mut provider = Provider::unlocked(ring)?;
    provider.configure_network(&endpoint)?;
    let scopes = BTreeSet::from([
        Scope::Accounts,
        Scope::PublicBalance,
        Scope::NftEnumeration,
        Scope::Transactions,
    ]);
    let access = provider.request_access(&app, scopes.clone(), now())?;
    assert!(provider.accounts(&app).is_err());
    provider.decide_access(&access, Some(Grant { accounts, scopes }), now())?;
    assert_eq!(provider.accounts(&app)?.len(), 6);
    assert!(provider.accounts(&other).is_err());
    let node = HttpNode::new(&endpoint)?;
    let registry_hex = std::env::args()
        .nth(2)
        .ok_or("Fixture registry image required")?;
    let source_evidence = source_review(
        &mut provider,
        &app,
        &node,
        &registry_hex,
        directory.path().join("receipts"),
    )?;
    let from = id(1)?;
    let to = id(2)?;
    let before = node.account(from)?;
    let proposal = json!({"kind":"native_transfer","from":from,"to":to,"amount":"1"});
    let request = provider.dispatch(
        &app,
        &json!({"method":"propose_transaction","proposal":proposal}).to_string(),
        now(),
    )?;
    let cancelled = request["id"].as_str().unwrap();
    assert!(matches!(
        provider.decide_configured_transaction(cancelled, false, now())?,
        TransactionState::Rejected
    ));
    assert_eq!(node.account(from)?.nonce, before.nonce);
    let mut transactions = vec![];
    transactions.push(perform(&mut provider, &app, proposal, &node)?);
    provider.configure_source_review(None);
    assert_eq!(node.account(from)?.balance, before.balance - 1);
    let balance = provider.dispatch(
        &app,
        &json!({"method":"native_balance","account":from}).to_string(),
        now(),
    )?;
    assert_eq!(balance["base_units"], (before.balance - 1).to_string());
    transactions.push(perform(
        &mut provider,
        &app,
        json!({"kind":"initialize_native","account":id(29)?}),
        &node,
    )?);
    assert_eq!(
        node.account(id(29)?)?.program_owner,
        programs::authenticated_transfer().id()
    );
    transactions.push(perform(
        &mut provider,
        &app,
        json!({"kind":"claim_vault","account":from,"amount":"1"}),
        &node,
    )?);
    assert_eq!(node.account(from)?.balance, before.balance);
    let holding = id(7)?;
    let before_token = provider.dispatch(
        &app,
        &json!({"method":"fungible_balance","holding":holding}).to_string(),
        now(),
    )?["token_base_units"]
        .as_str()
        .unwrap()
        .parse::<u128>()?;
    transactions.push(perform(&mut provider,&app,json!({"kind":"fungible_transfer","from":holding,"to":id(8)?,"definition":id(6)?,"amount":"1"}),&node)?);
    assert_eq!(
        provider.dispatch(
            &app,
            &json!({"method":"fungible_balance","holding":holding}).to_string(),
            now()
        )?["token_base_units"],
        (before_token - 1).to_string()
    );
    transactions.push(perform(
        &mut provider,
        &app,
        json!({"kind":"initialize_token","holding":id(30)?,"definition":id(6)?}),
        &node,
    )?);
    assert_eq!(
        provider.dispatch(
            &app,
            &json!({"method":"fungible_balance","holding":id(30)?}).to_string(),
            now()
        )?["token_base_units"],
        "0"
    );
    transactions.push(perform(
        &mut provider,
        &app,
        json!({"kind":"initialize_token","holding":id(28)?,"definition":id(21)?}),
        &node,
    )?);
    transactions.push(perform(
        &mut provider,
        &app,
        json!({"kind":"nft_transfer","from":id(25)?,"to":id(28)?,"collection":id(21)?}),
        &node,
    )?);
    assert_eq!(
        provider.dispatch(
            &app,
            &json!({"method":"nft_holding","holding":id(28)?}).to_string(),
            now()
        )?["state"]["NftPrintedCopy"]["owned"],
        true
    );
    assert_eq!(
        provider.dispatch(
            &app,
            &json!({"method":"nft_holding","holding":id(25)?}).to_string(),
            now()
        )?["state"]["NftPrintedCopy"]["owned"],
        false
    );
    drop(provider);
    let mut restored = Provider::unlocked(Keyring::open(&path, password)?)?;
    for (request_id, hash) in &transactions {
        let TransactionState::Submission { submission } =
            restored.transaction_status(&app, request_id, now())?
        else {
            return Err("Durable submission missing".into());
        };
        assert_eq!(submission.hash, *hash);
        assert_eq!(submission.state, SubmissionState::IncludedBySequencer);
        assert!(submission.last_checked_at.is_some());
        assert!(
            restored
                .transaction_status(&other, request_id, now())
                .is_err()
        );
    }
    println!(
        "{}",
        json!({"scope":"Rust provider domain against disposable local sequencer; no Basecamp GUI, testnet or adoption claim","transactions":transactions,"all_included_by_local_sequencer":true,"outbox_survives_restart":true,"confirmed_outbox_reconciliation":true,"cross_app_status_denied":true,"cancellation_preserved_nonce":true,"approval_reuse_rejected":true,"native_and_token_balances_checked":true,"nft_ownership_checked":true,"source_verification":source_evidence})
    );
    Ok(())
}
