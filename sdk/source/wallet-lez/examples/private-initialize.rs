// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real local-prover integration fixture, never an adoption or testnet claim.
use logos_registry_sdk::{AccountReader, HttpNode};
use logos_wallet_lez::{keyring::Keyring, shielded};
use logos_wallet_policy::{AppId, Grant, Policy, Scope};
#[derive(Clone, Copy, PartialEq, Eq)]
enum FixtureAsset {
    Native,
    Fungible,
    Nft,
}
impl FixtureAsset {
    fn is_token(self) -> bool {
        self != Self::Native
    }
    fn label(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Fungible => "fungible",
            Self::Nft => "nft_printed_copy",
        }
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = std::env::args().nth(1).ok_or("Missing loopback RPC")?;
    if !endpoint.starts_with("http://127.0.0.1:") {
        return Err("Only disposable loopback fixtures are accepted".into());
    }
    let asset = if std::env::args().any(|arg| arg == "--nft") {
        FixtureAsset::Nft
    } else if std::env::args().any(|arg| arg == "--token") {
        FixtureAsset::Fungible
    } else {
        FixtureAsset::Native
    };
    let directory = tempfile::tempdir()?;
    let mut ring = Keyring::create(
        &directory.path().join("private.sqlite"),
        b"local-fixture-password",
    )?;
    let account = ring.generate_private("Private fixture")?;
    let (keys, _) = ring.private_keys(account)?;
    let node = HttpNode::new(&endpoint)?;
    let app = AppId("local.fixture.private-initialize".into());
    let mut policy = Policy::default();
    policy.set_grant(
        app.clone(),
        Grant {
            accounts: [*account.value()].into_iter().collect(),
            scopes: [Scope::Transactions].into_iter().collect(),
        },
    )?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let prepared = if asset.is_token() {
        shielded::prepare_token_initialize(
            &mut policy,
            &app,
            &endpoint,
            &keys,
            0,
            token_definition(asset)?,
            now,
        )?
    } else {
        shielded::prepare_initialize(
            &mut policy,
            &app,
            &endpoint,
            &keys,
            0,
            node.commitment_root()?,
            now,
        )?
    };
    assert!(matches!(
        shielded::prove_initialize(&mut policy, &app, &prepared, &endpoint, &keys, now),
        Err(shielded::Error::Policy(_))
    ));
    policy.decide(prepared.prompt().id, true, now)?;
    eprintln!("Proving private initialization with the local r0vm; real receipts required");
    let proving_started = std::time::Instant::now();
    let proven = shielded::prove_initialize(&mut policy, &app, &prepared, &endpoint, &keys, now)?;
    assert!(
        shielded::prove_initialize(&mut policy, &app, &prepared, &endpoint, &keys, now).is_err()
    );
    let proving_seconds = proving_started.elapsed().as_secs_f64();
    ring.retain_private_initialization(&proven)?;
    let hash = proven.transaction().hash();
    drop(ring);
    let mut ring = Keyring::open(
        &directory.path().join("private.sqlite"),
        b"local-fixture-password",
    )?;
    assert_eq!(
        ring.pending_private_initialization(&endpoint, account)?,
        (hash, false)
    );
    assert_eq!(node.submit(proven.transaction())?, hash);
    for _ in 0..120 {
        if node.confirmed(hash)? {
            assert!(ring.confirm_private_initialization(&endpoint, account)?);
            drop(ring);
            let mut ring = Keyring::open(
                &directory.path().join("private.sqlite"),
                b"local-fixture-password",
            )?;
            assert_eq!(
                ring.pending_private_initialization(&endpoint, account)?,
                (hash, true)
            );
            let roundtrip = if std::env::args().any(|arg| arg == "--roundtrip") {
                Some(roundtrip_native(
                    &endpoint,
                    &node,
                    &keys,
                    account,
                    proven.pending_state().clone(),
                    &mut ring,
                    asset,
                )?)
            } else {
                None
            };
            println!(
                "{}",
                serde_json::json!({"private_initialization": hash, "asset_kind":asset.label(), "roundtrip":roundtrip, "real_proof_verified": true, "proving_seconds":proving_seconds, "pending_and_included_survive_restart":true, "commitment_membership_verified":true, "encrypted_output_verified": true, "unapproved_rejected": true, "approval_reuse_rejected": true, "scope": "disposable local fixture; no public deployment or adoption"})
            );
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err("Proven initialization was not confirmed within 60 seconds".into())
}

fn roundtrip_native(
    endpoint: &str,
    node: &HttpNode,
    keys: &key_protocol::key_management::secret_holders::PrivateKeyHolder,
    private_account: lee::AccountId,
    mut private_state: lee::Account,
    ring: &mut Keyring,
    asset: FixtureAsset,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    use logos_wallet_lez::shielded_transfer::{self, Direction, Transfer};
    let public_key = lee::PrivateKey::try_new(
        [match asset {
            FixtureAsset::Native => 1,
            FixtureAsset::Fungible => 7,
            FixtureAsset::Nft => 25,
        }; 32],
    )?;
    let public_account = lee::AccountId::from(&lee::PublicKey::new_from_private_key(&public_key));
    let public_before = balance(&node.account(public_account)?, asset)?;
    let app = AppId("local.fixture.shielded-roundtrip".into());
    let mut policy = Policy::default();
    policy.set_grant(
        app.clone(),
        Grant {
            accounts: [*private_account.value(), *public_account.value()]
                .into_iter()
                .collect(),
            scopes: [Scope::Transactions].into_iter().collect(),
        },
    )?;
    let mut evidence = vec![];
    for (direction, amount, label) in [
        (
            Direction::Deposit,
            if asset == FixtureAsset::Nft { 1 } else { 25 },
            "deposit",
        ),
        (
            Direction::Withdrawal,
            if asset == FixtureAsset::Nft { 1 } else { 10 },
            "withdrawal",
        ),
    ] {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let transfer = Transfer {
            public_account,
            private_account,
            private_state: private_state.clone(),
            identifier: 0,
            direction,
            amount,
        };
        let prepared = if asset == FixtureAsset::Nft {
            shielded_transfer::prepare_nft(
                &mut policy,
                &app,
                endpoint,
                transfer,
                token_definition(asset)?,
                now,
            )?
        } else if asset.is_token() {
            shielded_transfer::prepare_token(
                &mut policy,
                &app,
                endpoint,
                transfer,
                token_definition(asset)?,
                now,
            )?
        } else {
            shielded_transfer::prepare(&mut policy, &app, endpoint, transfer, now)?
        };
        let signer = if direction == Direction::Deposit {
            Some(&public_key)
        } else {
            None
        };
        assert!(matches!(
            shielded_transfer::prove(&mut policy, &app, &prepared, endpoint, keys, signer, now),
            Err(shielded::Error::Policy(_))
        ));
        policy.decide(prepared.prompt().id, true, now)?;
        assert!(
            shielded_transfer::prove(
                &mut policy,
                &app,
                &prepared,
                "http://127.0.0.1:1",
                keys,
                signer,
                now
            )
            .is_err()
        );
        eprintln!("Proving {} {label} with the local r0vm", asset.label());
        let started = std::time::Instant::now();
        let proven =
            shielded_transfer::prove(&mut policy, &app, &prepared, endpoint, keys, signer, now)?;
        let seconds = started.elapsed().as_secs_f64();
        assert!(
            shielded_transfer::prove(&mut policy, &app, &prepared, endpoint, keys, signer, now)
                .is_err()
        );
        ring.retain_private_transfer(&proven)?;
        let hash = node.submit(proven.transaction())?;
        let mut included = false;
        for _ in 0..120 {
            if node.confirmed(hash)? {
                included = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        if !included {
            return Err("Shielded native transaction did not confirm".into());
        }
        assert!(ring.confirm_private_operation(endpoint, private_account)?);
        private_state = ring.last_included_private_state(endpoint, private_account)?;
        assert_eq!(&private_state, proven.pending_state());
        node.commitment_membership(lee_core::Commitment::new(&private_account, &private_state))?;
        let private_units = balance(&private_state, asset)?;
        let public_units = balance(&node.account(public_account)?, asset)?;
        if asset == FixtureAsset::Nft {
            assert_eq!(
                (public_units, private_units),
                if direction == Direction::Deposit {
                    (0, 1)
                } else {
                    (1, 0)
                }
            );
        }
        evidence.push(serde_json::json!({"direction":label,"transaction":hash,"proving_seconds":seconds,"private_units_or_ownership":private_units.to_string(),"public_units_or_ownership":public_units.to_string()}));
    }
    let retained = if asset == FixtureAsset::Nft { 0 } else { 15 };
    assert_eq!(
        balance(&node.account(public_account)?, asset)?,
        public_before - retained
    );
    assert_eq!(balance(&private_state, asset)?, retained);
    let mut synced = ring.sync_private(endpoint, private_account, 64)?;
    for _ in 0..128 {
        if synced.caught_up_to_observed_tip {
            break;
        }
        synced = ring.sync_private(endpoint, private_account, 64)?;
    }
    assert!(synced.caught_up_to_observed_tip);
    if asset == FixtureAsset::Nft {
        assert!(matches!(
            synced.token_holding,
            Some(logos_wallet_lez::token::HoldingView::NftPrintedCopy { owned: false, .. })
        ));
        assert_eq!(synced.native_base_units.as_deref(), Some("0"));
    } else if asset.is_token() {
        assert!(
            matches!(synced.token_holding, Some(logos_wallet_lez::token::HoldingView::Fungible { balance, .. }) if balance == "15")
        );
        assert_eq!(synced.native_base_units.as_deref(), Some("0"));
    } else {
        assert_eq!(synced.native_base_units.as_deref(), Some("15"));
        assert!(synced.token_holding.is_none());
    }

    Ok(
        serde_json::json!({"operations":evidence,"public_balance_delta":-(retained as i128),"private_balance":retained,"unapproved_and_reused_approvals_rejected":true,"endpoint_switch_rejected":true,"scope":"local deposit/withdrawal fixtures; not private-to-private transfers, public deployment or adoption"}),
    )
}

fn token_definition(asset: FixtureAsset) -> Result<lee::AccountId, Box<dyn std::error::Error>> {
    Ok(lee::AccountId::from(&lee::PublicKey::new_from_private_key(
        &lee::PrivateKey::try_new([if asset == FixtureAsset::Nft { 21 } else { 6 }; 32])?,
    )))
}
fn balance(state: &lee::Account, asset: FixtureAsset) -> Result<u128, Box<dyn std::error::Error>> {
    if !asset.is_token() {
        return Ok(state.balance);
    }
    match token_core::TokenHolding::try_from(&state.data)? {
        token_core::TokenHolding::Fungible {
            definition_id,
            balance,
        } if definition_id == token_definition(asset)? => Ok(balance),
        token_core::TokenHolding::NftPrintedCopy {
            definition_id,
            owned,
        } if asset == FixtureAsset::Nft && definition_id == token_definition(asset)? => {
            Ok(u128::from(owned))
        }
        _ => Err("Unexpected fixture token holding".into()),
    }
}
