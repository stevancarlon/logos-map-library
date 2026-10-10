// SPDX-License-Identifier: MIT OR Apache-2.0
//! Genuine local proofs for two wallet-owned private accounts; no adoption claim.
use lee::{Account, AccountId, PrivateKey, PublicKey};
use logos_registry_sdk::{AccountReader, HttpNode};
use logos_wallet_lez::{
    keyring::Keyring,
    private_transfer::{self, Opening, TransferRequest},
    shielded,
    shielded_transfer::{self, Asset, Direction, Transfer},
};
use logos_wallet_policy::{AppId, Grant, Policy, Scope};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}
fn fixture_id(byte: u8) -> Result<AccountId> {
    Ok(AccountId::from(&PublicKey::new_from_private_key(
        &PrivateKey::try_new([byte; 32])?,
    )))
}
fn units(state: &Account, asset: Asset) -> Result<u128> {
    Ok(match asset {
        Asset::Native => state.balance,
        Asset::Fungible(id) => match token_core::TokenHolding::try_from(&state.data)? {
            token_core::TokenHolding::Fungible {
                definition_id,
                balance,
            } if definition_id == id => balance,
            _ => return Err("Wrong fungible state".into()),
        },
        Asset::Nft(id) => match token_core::TokenHolding::try_from(&state.data)? {
            token_core::TokenHolding::NftPrintedCopy {
                definition_id,
                owned,
            } if definition_id == id => u128::from(owned),
            _ => return Err("Wrong NFT state".into()),
        },
    })
}
fn submit(node: &HttpNode, transaction: &common::transaction::LeeTransaction) -> Result<()> {
    let hash = transaction.hash();
    assert_eq!(node.submit(transaction)?, hash);
    for _ in 0..120 {
        if node.confirmed(hash)? {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err("Private fixture transaction not included".into())
}
fn main() -> Result<()> {
    let endpoint = std::env::args().nth(1).ok_or("Missing loopback endpoint")?;
    if !endpoint.starts_with("http://127.0.0.1:") {
        return Err("Only disposable loopback fixtures allowed".into());
    }
    let mode = std::env::args()
        .nth(2)
        .ok_or("Specify native, fungible or nft")?;
    let (asset, fixture_key, deposit_amount, transfer_amount) = match mode.as_str() {
        "native" => (Asset::Native, 1, 25, 9),
        "fungible" => (Asset::Fungible(fixture_id(6)?), 7, 25, 9),
        "nft" => (Asset::Nft(fixture_id(21)?), 25, 1, 1),
        _ => return Err("Unknown private pair asset".into()),
    };
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("private-pair.sqlite");
    let password = b"disposable private pair fixture";
    let mut ring = Keyring::create(&path, password)?;
    let from = ring.generate_private("Private source")?;
    let to = ring.generate_private("Private recipient")?;
    let (from_keys, from_kind) = ring.private_keys(from)?;
    let (to_keys, to_kind) = ring.private_keys(to)?;
    let lee_core::PrivateAccountKind::Regular(from_identifier) = from_kind else {
        return Err("Expected regular source".into());
    };
    let lee_core::PrivateAccountKind::Regular(to_identifier) = to_kind else {
        return Err("Expected regular recipient".into());
    };
    let public_key = PrivateKey::try_new([fixture_key; 32])?;
    let public = AccountId::from(&PublicKey::new_from_private_key(&public_key));
    let app = AppId("local.fixture.private-pair".into());
    let mut policy = Policy::default();
    let grant = Grant {
        accounts: [*from.value(), *to.value(), *public.value()]
            .into_iter()
            .collect(),
        scopes: [Scope::Transactions].into_iter().collect(),
    };
    policy.set_grant(app.clone(), grant.clone())?;
    let node = HttpNode::new(&endpoint)?;
    let mut initializations = Vec::new();
    for (account, keys, identifier) in [
        (from, &from_keys, from_identifier),
        (to, &to_keys, to_identifier),
    ] {
        let time = now()?;
        let prepared = match asset {
            Asset::Native => shielded::prepare_initialize(
                &mut policy,
                &app,
                &endpoint,
                keys,
                identifier,
                node.commitment_root()?,
                time,
            )?,
            Asset::Fungible(id) | Asset::Nft(id) => shielded::prepare_token_initialize(
                &mut policy,
                &app,
                &endpoint,
                keys,
                identifier,
                id,
                time,
            )?,
        };
        policy.decide(prepared.prompt().id, true, time)?;
        eprintln!(
            "Proving {mode} private holding initialization {}",
            initializations.len() + 1
        );
        let proven =
            shielded::prove_initialize(&mut policy, &app, &prepared, &endpoint, keys, time)?;
        ring.retain_private_initialization(&proven)?;
        submit(&node, proven.transaction())?;
        assert!(ring.confirm_private_operation(&endpoint, account)?);
        initializations.push(proven.transaction().hash());
    }
    let time = now()?;
    let transfer = Transfer {
        public_account: public,
        private_account: from,
        private_state: ring.last_included_private_state(&endpoint, from)?,
        identifier: from_identifier,
        direction: Direction::Deposit,
        amount: deposit_amount,
    };
    let prepared = match asset {
        Asset::Native => shielded_transfer::prepare(&mut policy, &app, &endpoint, transfer, time)?,
        Asset::Fungible(id) => {
            shielded_transfer::prepare_token(&mut policy, &app, &endpoint, transfer, id, time)?
        }
        Asset::Nft(id) => {
            shielded_transfer::prepare_nft(&mut policy, &app, &endpoint, transfer, id, time)?
        }
    };
    policy.decide(prepared.prompt().id, true, time)?;
    eprintln!("Proving {mode} fixture deposit");
    let deposit = shielded_transfer::prove(
        &mut policy,
        &app,
        &prepared,
        &endpoint,
        &from_keys,
        Some(&public_key),
        time,
    )?;
    ring.retain_private_transfer(&deposit)?;
    submit(&node, deposit.transaction())?;
    assert!(ring.confirm_private_operation(&endpoint, from)?);
    let public_before = node.account(public)?;
    let time = now()?;
    let prepared = private_transfer::prepare(
        &mut policy,
        &app,
        &endpoint,
        TransferRequest {
            from: Opening {
                account: from,
                state: ring.last_included_private_state(&endpoint, from)?,
                identifier: from_identifier,
            },
            to: Opening {
                account: to,
                state: ring.last_included_private_state(&endpoint, to)?,
                identifier: to_identifier,
            },
            asset,
            amount: transfer_amount,
        },
        time,
    )?;
    assert!(
        private_transfer::prove(
            &mut policy,
            &app,
            &prepared,
            &endpoint,
            [&from_keys, &to_keys],
            time
        )
        .is_err()
    );
    policy.decide(prepared.prompt().id, true, time)?;
    assert!(
        private_transfer::prove(
            &mut policy,
            &app,
            &prepared,
            "http://127.0.0.1:1",
            [&from_keys, &to_keys],
            time
        )
        .is_err()
    );
    assert!(
        private_transfer::prove(
            &mut policy,
            &app,
            &prepared,
            &endpoint,
            [&to_keys, &from_keys],
            time
        )
        .is_err()
    );
    eprintln!("Proving {mode} private-to-private transfer");
    let started = std::time::Instant::now();
    let proven = private_transfer::prove(
        &mut policy,
        &app,
        &prepared,
        &endpoint,
        [&from_keys, &to_keys],
        time,
    )?;
    let proving_seconds = started.elapsed().as_secs_f64();
    assert!(
        private_transfer::prove(
            &mut policy,
            &app,
            &prepared,
            &endpoint,
            [&from_keys, &to_keys],
            time
        )
        .is_err()
    );
    ring.retain_private_transfers(&[&proven[0], &proven[1]])?;
    let hash = proven[0].transaction().hash();
    drop(ring);
    let mut ring = Keyring::open(&path, password)?;
    for account in [from, to] {
        assert_eq!(
            ring.pending_private_operation(&endpoint, account)?,
            (hash, false)
        );
    }
    submit(&node, proven[0].transaction())?;
    for account in [from, to] {
        assert!(ring.confirm_private_operation(&endpoint, account)?);
    }
    drop(ring);
    let ring = Keyring::open(&path, password)?;
    let sender = ring.last_included_private_state(&endpoint, from)?;
    let recipient = ring.last_included_private_state(&endpoint, to)?;
    assert_eq!(units(&sender, asset)?, deposit_amount - transfer_amount);
    assert_eq!(units(&recipient, asset)?, transfer_amount);
    assert_eq!(node.account(public)?, public_before);
    for (account, state) in [(from, &sender), (to, &recipient)] {
        node.commitment_membership(lee_core::Commitment::new(&account, state))?;
    }
    let cli = if std::env::args().any(|arg| arg == "--cli-after-sdk") {
        drop(ring);
        eprintln!("Proving reverse {mode} transfer through terminal approval");
        let helper = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../scripts/test-private-pair-cli.py");
        let mut command = std::process::Command::new("python3");
        command
            .arg(helper)
            .args(["--rpc", &endpoint, "--wallet"])
            .arg(&path)
            .args([
                "--asset",
                &mode,
                "--source",
                &to.to_string(),
                "--recipient",
                &from.to_string(),
                "--amount",
                &transfer_amount.to_string(),
            ]);
        match asset {
            Asset::Native => {}
            Asset::Fungible(id) | Asset::Nft(id) => {
                command.args(["--definition", &id.to_string()]);
            }
        }
        let output = command.output()?;
        if !output.status.success() {
            return Err(format!(
                "Private pair CLI fixture failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        let cli: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let restored = Keyring::open(&path, password)?;
        assert_eq!(
            units(
                &restored.last_included_private_state(&endpoint, from)?,
                asset
            )?,
            deposit_amount
        );
        assert_eq!(
            units(&restored.last_included_private_state(&endpoint, to)?, asset)?,
            0
        );
        assert_eq!(node.account(public)?, public_before);
        Some(cli)
    } else {
        None
    };
    println!(
        "{}",
        serde_json::json!({"asset":mode,"reverse_cli":cli,"initializations":initializations,"deposit":deposit.transaction().hash(),"private_transfer":hash,"proving_seconds":proving_seconds,"source_units_or_ownership":units(&sender,asset)?.to_string(),"recipient_units_or_ownership":units(&recipient,asset)?.to_string(),"both_pending_states_survive_restart":true,"both_included_states_survive_restart":true,"both_commitments_checked":true,"unapproved_reused_wrong_endpoint_and_swapped_keys_rejected":true,"public_account_unchanged_by_private_transfer":true,"scope":"genuine local proofs between two initialized wallet-owned private accounts; no external recipient, testnet, membership proof or adoption"})
    );
    Ok(())
}
