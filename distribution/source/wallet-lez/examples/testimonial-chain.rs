// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real disposable LEZ execution; synthetic testimonials never count as adoption.
use common::transaction::LeeTransaction;
use lee::{
    AccountId, PrivateKey, PublicKey, PublicTransaction,
    public_transaction::{Message, WitnessSet},
};
use logos_registry_sdk::{AccountReader, HttpNode};
use logos_testimonial::{Content, Instruction, Testimonial};
use logos_wallet_lez::{
    keyring::{Keyring, public_outbox::SubmissionState},
    provider::{Provider, transactions::TransactionState},
};
use logos_wallet_policy::{Grant, Scope, principal::Principal};
use serde_json::{Value, json};
use spel_framework::prelude::{ToSeed, compute_pda, seed_from_str};
use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn included(node: &HttpNode, tx: LeeTransaction) -> Result<common::HashType> {
    let hash = node.submit(&tx)?;
    for _ in 0..120 {
        if node.confirmed(hash)? {
            return Ok(hash);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err("Testimonial fixture transaction was not included".into())
}
fn signed(
    node: &HttpNode,
    program: [u32; 8],
    key: &PrivateKey,
    accounts: Vec<AccountId>,
    instruction: Instruction,
) -> Result<LeeTransaction> {
    let author = AccountId::from(&PublicKey::new_from_private_key(key));
    let message = Message::try_new(
        program,
        accounts,
        vec![node.account(author)?.nonce],
        instruction,
    )?;
    let witness = WitnessSet::for_message(&message, &[key]);
    Ok(LeeTransaction::Public(PublicTransaction::new(
        message, witness,
    )))
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn approve(
    provider: &mut Provider,
    app: &Principal,
    node: &HttpNode,
    proposal: Value,
) -> Result<common::HashType> {
    let request = provider.dispatch(
        app,
        &json!({"method":"propose_transaction","proposal":proposal}).to_string(),
        now(),
    )?;
    let id = request["id"].as_str().ok_or("Missing proposal")?;
    assert!(matches!(
        provider.transaction_status(app, id, now())?,
        TransactionState::Pending
    ));
    let TransactionState::Submission { submission } =
        provider.decide_configured_transaction(id, true, now())?
    else {
        return Err("Missing submission".into());
    };
    assert_eq!(submission.state, SubmissionState::Submitted);
    assert!(
        provider
            .decide_configured_transaction(id, true, now())
            .is_err()
    );
    for _ in 0..120 {
        if node.confirmed(submission.hash)? {
            return Ok(submission.hash);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err("Provider testimonial submission not included".into())
}
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err("RPC PROGRAM_BINARY required".into());
    }
    args[1]
        .strip_prefix("http://127.0.0.1:")
        .ok_or("Disposable loopback only")?
        .parse::<u16>()?;
    let node = HttpNode::new(&args[1])?;
    let binary = std::fs::read(&args[2])?;
    let program: [u32; 8] = risc0_binfmt::compute_image_id(&binary)?
        .as_words()
        .try_into()?;
    assert_eq!(
        program,
        logos_registry_sdk::parse_program(logos_wallet_lez::testimonial::PROGRAM_HEX)?
    );
    let deployment = included(
        &node,
        LeeTransaction::ProgramDeployment(lee::ProgramDeploymentTransaction::new(
            lee::program_deployment_transaction::Message::new(binary),
        )),
    )?;
    let key = PrivateKey::try_new([1; 32])?;
    let author = AccountId::from(&PublicKey::new_from_private_key(&key));
    let catalog = compute_pda(&program, &[&seed_from_str("testimonials")]);
    let page = compute_pda(
        &program,
        &[&seed_from_str("testimonial-page"), &0u64.to_seed()],
    );
    let entry = compute_pda(&program, &[&seed_from_str("testimonial"), &0u64.to_seed()]);
    let directory = tempfile::tempdir()?;
    let mut keyring = Keyring::create(
        &directory.path().join("wallet.sqlite"),
        b"testimonial provider fixture",
    )?;
    keyring.import_public("Synthetic testimonial author", &[1; 32])?;
    let mut provider = Provider::unlocked(keyring)?;
    provider.configure_network(&args[1])?;
    let app = Principal::Module {
        name: "testimonial_fixture".into(),
        instance: String::new(),
    };
    let scopes = BTreeSet::from([Scope::Accounts, Scope::Transactions]);
    let access = provider.request_access(&app, scopes.clone(), now())?;
    assert!(provider.accounts(&app).is_err());
    provider.decide_access(
        &access,
        Some(Grant {
            accounts: BTreeSet::from([*author.value()]),
            scopes,
        }),
        now(),
    )?;
    assert_eq!(provider.accounts(&app)?.len(), 1);
    approve(
        &mut provider,
        &app,
        &node,
        json!({"kind":"initialize_testimonials","account":author}),
    )?;
    approve(
        &mut provider,
        &app,
        &node,
        json!({"kind":"create_testimonial_page","account":author,"number":0}),
    )?;
    let content = Content {
        submission_id: "LP-0021-local-fixture".into(),
        username: "Synthetic fixture".into(),
        text: "This is an automated local test, not authentic adoption.".into(),
    };
    let publication = approve(
        &mut provider,
        &app,
        &node,
        json!({"kind":"publish_testimonial","account":author,"content":content}),
    )?;
    let stored = node.account(entry)?;
    if stored.program_owner != program {
        return Err("Wrong testimonial owner".into());
    }
    let value: Testimonial = borsh::from_slice(&Vec::<u8>::from(stored.data.clone()))?;
    assert_eq!(value.author, *author.value());
    assert_eq!(value.content, content);
    let before = node.account(author)?;
    let duplicate = signed(
        &node,
        program,
        &key,
        vec![catalog, page, entry, author],
        Instruction::Publish {
            page_number: 0,
            ordinal: 0,
            submitted_at: 0,
            content_json: serde_json::to_string(&content)?,
        },
    )?;
    let duplicate_hash = node.submit(&duplicate)?;
    for _ in 0..10 {
        assert!(!node.confirmed(duplicate_hash)?);
        std::thread::sleep(Duration::from_millis(500));
    }
    assert_eq!(node.account(entry)?, stored);
    assert_eq!(node.account(author)?, before);
    println!(
        "{}",
        json!({"result":"passed","program":logos_registry_sdk::program_bytes(&program).iter().map(|b|format!("{b:02x}")).collect::<String>(),"deployment":deployment,"publication":publication,"entry":entry,"stored":value,"duplicate_rejected":true,"provider_account_selection":true,"provider_explicit_approval":true,"approval_reuse_rejected":true,"scope":"actual disposable sequencer + wallet provider SDK; synthetic testimonial, no GUI, official zone or adoption claim"})
    );
    Ok(())
}
