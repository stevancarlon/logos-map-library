// SPDX-License-Identifier: MIT OR Apache-2.0
//! Trusted local CLI. This is not an authenticated dApp provider.
use lee::{AccountId, PublicKey};
use logos_wallet_lez::keyring::Keyring;
use logos_wallet_lez::{
    NativeTransfer, NativeWallet,
    token::{FungibleTransfer, NftTransfer},
};
use logos_wallet_policy::{AppId, Grant, Policy, Scope};
use std::{
    collections::BTreeSet,
    error::Error,
    io::{BufRead, Read, Write},
    path::Path,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

fn now() -> Result<u64, Box<dyn Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn policy(account: [u8; 32]) -> Result<(Policy, AppId), Box<dyn Error>> {
    let app = AppId("local.wallet.cli".into());
    let mut policy = Policy::default();
    policy.set_grant(
        app.clone(),
        Grant {
            accounts: BTreeSet::from([account]),
            scopes: BTreeSet::from([Scope::PublicBalance, Scope::Transactions]),
        },
    )?;
    Ok((policy, app))
}
fn approve() -> Result<bool, Box<dyn Error>> {
    // Deliberately no --yes flag or stdin approval: signing requires a live terminal.
    let mut terminal = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")?;
    terminal
        .write_all(b"Type APPROVE to authorize this exact request, or anything else to cancel: ")?;
    terminal.flush()?;
    let mut answer = String::new();
    std::io::BufReader::new(terminal)
        .take(128)
        .read_line(&mut answer)?;
    Ok(answer.trim() == "APPROVE")
}
fn public_cli_principal() -> logos_wallet_policy::principal::Principal {
    // Local terminal authority, not a claim of authenticated Basecamp dispatch.
    logos_wallet_policy::principal::Principal::LocalCli
}
fn run_nft_new_holding(args: &[String]) -> Result<(), Box<dyn Error>> {
    use rand_core::{OsRng, RngCore};
    let endpoint = args[2].trim_end_matches('/');
    let source = AccountId::from_str(&args[5])?;
    let recipient = AccountId::from_str(&args[6])?;
    let collection = AccountId::from_str(&args[4])?;
    let password = Zeroizing::new(logos_registry_sdk::terminal::prompt_secret(
        "Wallet password: ",
    )?);
    let mut ring = Keyring::open(Path::new(&args[3]), password.as_bytes())?;
    drop(password);
    let source_key = ring.signing_key(source)?;
    let recipient_key = ring.signing_key(recipient)?;
    let (mut policy, app) = policy(*source.value())?;
    policy.set_grant(
        app.clone(),
        Grant {
            accounts: [*source.value(), *recipient.value()].into_iter().collect(),
            scopes: [Scope::Transactions].into_iter().collect(),
        },
    )?;
    let wallet = NativeWallet::connect(endpoint)?;
    let prepared = wallet.prepare_nft_to_new_holding(
        &mut policy,
        &app,
        NftTransfer {
            from: *source.value(),
            to: *recipient.value(),
            collection: *collection.value(),
        },
        now()?,
    )?;
    eprintln!(
        "Requesting application: local wallet CLI\nSequencer: {}\nSource holding: {source}\nFresh recipient: {recipient}\nCollection: {collection}\nBoth wallet accounts sign. Program source is not locally verified. Fees are not estimated.\n{}",
        args[2],
        serde_json::to_string_pretty(prepared.prompt())?
    );
    if !approve()? {
        policy.decide(prepared.prompt().id, false, now()?)?;
        return Err("Canceled without signing or submitting".into());
    }
    ring.ensure_current()?;
    policy.decide(prepared.prompt().id, true, now()?)?;
    let transaction = wallet.sign_approved_with_keys(
        &mut policy,
        &app,
        &prepared,
        &[&source_key, &recipient_key],
        now()?,
    )?;
    let mut bytes = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| "Secure request ID unavailable")?;
    let id = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let hash =
        ring.retain_public_submission(&id, &public_cli_principal(), endpoint, transaction.clone())?;
    eprintln!(
        "Saved request: {id}\nSaved transaction: {hash}\nCheck this saved request after an interruption; do not blindly repeat the transfer."
    );
    let acknowledged = logos_registry_sdk::HttpNode::new(endpoint)?
        .submit(&transaction)
        .is_ok_and(|returned| returned == hash);
    ring.mark_public_submission(&id, acknowledged)?;
    println!(
        "{}",
        serde_json::json!({"request_id":id,"transaction":hash,"status":if acknowledged {"submitted"} else {"uncertain"},"confirmed":false})
    );
    Ok(())
}
fn run_private_pair(operation: &str, args: &[String]) -> Result<(), Box<dyn Error>> {
    use logos_wallet_lez::{
        private_transfer::{self, Opening, TransferRequest},
        shielded,
        shielded_transfer::Asset,
    };
    shielded::require_local_prover()?;
    let endpoint = &args[2];
    let offset = if operation == "private-transfer" {
        4
    } else {
        5
    };
    let from = AccountId::from_str(&args[offset])?;
    let to = AccountId::from_str(&args[offset + 1])?;
    let amount = args[offset + 2].parse()?;
    let asset = match operation {
        "private-transfer" => Asset::Native,
        "private-token-transfer" => Asset::Fungible(AccountId::from_str(&args[4])?),
        "private-nft-transfer" => Asset::Nft(AccountId::from_str(&args[4])?),
        _ => return Err("Unknown private pair operation".into()),
    };
    let password = Zeroizing::new(logos_registry_sdk::terminal::prompt_secret(
        "Wallet password: ",
    )?);
    let mut ring = Keyring::open(Path::new(&args[3]), password.as_bytes())?;
    drop(password);
    let (from_keys, from_kind) = ring.private_keys(from)?;
    let (to_keys, to_kind) = ring.private_keys(to)?;
    let lee_core::PrivateAccountKind::Regular(from_identifier) = from_kind else {
        return Err("Only regular private accounts are supported".into());
    };
    let lee_core::PrivateAccountKind::Regular(to_identifier) = to_kind else {
        return Err("Only regular private accounts are supported".into());
    };
    let (mut policy, app) = policy(*from.value())?;
    policy.set_grant(
        app.clone(),
        Grant {
            accounts: [*from.value(), *to.value()].into_iter().collect(),
            scopes: [Scope::Transactions].into_iter().collect(),
        },
    )?;
    let prepared = private_transfer::prepare(
        &mut policy,
        &app,
        endpoint,
        TransferRequest {
            from: Opening {
                account: from,
                state: ring.last_included_private_state(endpoint, from)?,
                identifier: from_identifier,
            },
            to: Opening {
                account: to,
                state: ring.last_included_private_state(endpoint, to)?,
                identifier: to_identifier,
            },
            asset,
            amount,
        },
        now()?,
    )?;
    eprintln!(
        "Private source: {from}\nPrivate recipient: {to}\nBoth private accounts belong to this wallet. Local proving may take several minutes.\nProgram source verification: not locally verified. Fees are not estimated.\n{}",
        serde_json::to_string_pretty(prepared.prompt())?
    );
    if !approve()? {
        return Err("Canceled without proving or submitting".into());
    }
    ring.ensure_current()?;
    policy.decide(prepared.prompt().id, true, now()?)?;
    let proven = private_transfer::prove(
        &mut policy,
        &app,
        &prepared,
        endpoint,
        [&from_keys, &to_keys],
        now()?,
    )?;
    ring.retain_private_transfers(&[&proven[0], &proven[1]])?;
    let hash = proven[0].transaction().hash();
    eprintln!(
        "Saved transaction for both private accounts: {hash}\nSelect each private account and run private-status on the original node after an interruption. Do not blindly repeat the transfer."
    );
    let acknowledged = logos_registry_sdk::HttpNode::new(endpoint)?
        .submit(proven[0].transaction())
        .is_ok_and(|returned| returned == hash);
    println!(
        "{}",
        serde_json::json!({"transaction":hash,"status":if acknowledged {"submitted"} else {"uncertain"},"confirmed":false,"private_accounts":[from,to],"recovery":"both pending states saved atomically; select each account and run private-status"})
    );
    Ok(())
}

fn run_private(operation: &str, args: &[String]) -> Result<(), Box<dyn Error>> {
    use logos_wallet_lez::{
        shielded,
        shielded_transfer::{self, Direction, Transfer},
    };
    if matches!(
        operation,
        "private-initialize"
            | "private-token-initialize"
            | "shield"
            | "unshield"
            | "token-shield"
            | "token-unshield"
            | "nft-shield"
            | "nft-unshield"
    ) {
        shielded::require_local_prover()?;
    }
    let endpoint = &args[2];
    let password = Zeroizing::new(logos_registry_sdk::terminal::prompt_secret(
        "Wallet password: ",
    )?);
    let mut ring = Keyring::open(Path::new(&args[3]), password.as_bytes())?;
    drop(password);
    let node = logos_registry_sdk::HttpNode::new(endpoint)?;
    if operation == "sync-private" {
        let account = ring.selected_account()?;
        let max_blocks = args.get(4).map(|v| v.parse()).transpose()?.unwrap_or(32);
        println!(
            "{}",
            serde_json::to_string(&ring.sync_private(endpoint, account, max_blocks)?)?
        );
        return Ok(());
    }
    if operation == "recover-private" {
        let account = ring.selected_account()?;
        let hash = args[4].parse()?;
        let recovered = ring.recover_private_transaction(endpoint, account, hash)?;
        println!(
            "{}",
            serde_json::json!({"recovered":recovered,"synchronized":false,"scope":"state as of the specified transaction; no automatic chain scan or consensus finality"})
        );
        return Ok(());
    }
    if operation == "private-status" {
        let account = ring.selected_account()?;
        let (hash, _) = ring.pending_private_operation(endpoint, account)?;
        let included = ring.confirm_private_operation(endpoint, account)?;
        let token_holding = if included {
            let state = ring.last_included_private_state(endpoint, account)?;
            if state.program_owner == programs::token().id() {
                Some(logos_wallet_lez::token::HoldingView::from(
                    token_core::TokenHolding::try_from(&state.data)?,
                ))
            } else {
                None
            }
        } else {
            None
        };
        println!(
            "{}",
            serde_json::json!({"transaction":hash,"included":included,"token_holding_at_transaction":token_holding,"native_base_units_at_transaction":if included {Some(ring.last_included_private_state(endpoint,account)?.balance.to_string())} else {None},"synchronized":false,"scope":"sequencer inclusion; balance is as of this transaction, not a claim of synchronization or consensus finality"})
        );
        return Ok(());
    }
    if matches!(operation, "private-initialize" | "private-token-initialize") {
        let account = ring.selected_account()?;
        let (keys, kind) = ring.private_keys(account)?;
        if ring.pending_private_operation(endpoint, account).is_ok() {
            return Err(
                "Private operation already recorded; use private-status before another operation"
                    .into(),
            );
        }
        let lee_core::PrivateAccountKind::Regular(identifier) = kind else {
            return Err("Only regular private accounts are supported".into());
        };
        let (mut policy, app) = policy(*account.value())?;
        let prepared = if operation == "private-token-initialize" {
            shielded::prepare_token_initialize(
                &mut policy,
                &app,
                endpoint,
                &keys,
                identifier,
                AccountId::from_str(&args[4])?,
                now()?,
            )?
        } else {
            shielded::prepare_initialize(
                &mut policy,
                &app,
                endpoint,
                &keys,
                identifier,
                node.commitment_root()?,
                now()?,
            )?
        };
        eprintln!(
            "Private initialization uses the local prover and may take several minutes.\nProgram source verification: not locally verified. Fees are not estimated.\n{}",
            serde_json::to_string_pretty(prepared.prompt())?
        );
        if !approve()? {
            return Err("Canceled without proving or submitting".into());
        }
        policy.decide(prepared.prompt().id, true, now()?)?;
        let proven =
            shielded::prove_initialize(&mut policy, &app, &prepared, endpoint, &keys, now()?)?;
        ring.retain_private_initialization(&proven)?;
        let hash = proven.transaction().hash();
        node.submit(proven.transaction())
            .map_err(|source| logos_wallet_lez::Error::Submission { hash, source })?;
        println!(
            "{}",
            serde_json::json!({"transaction":hash,"status":"submitted","confirmed":false,"recovery":"saved in encrypted wallet; use private-status"})
        );
        return Ok(());
    }
    let nft = matches!(operation, "nft-shield" | "nft-unshield");
    let token = nft || matches!(operation, "token-shield" | "token-unshield");
    let offset = if token { 5 } else { 4 };
    let from = AccountId::from_str(&args[offset])?;
    let to = AccountId::from_str(&args[offset + 1])?;
    let direction = if matches!(operation, "shield" | "token-shield" | "nft-shield") {
        Direction::Deposit
    } else {
        Direction::Withdrawal
    };
    let (public_account, private_account) = if direction == Direction::Deposit {
        (from, to)
    } else {
        (to, from)
    };
    let (keys, kind) = ring.private_keys(private_account)?;
    let lee_core::PrivateAccountKind::Regular(identifier) = kind else {
        return Err("Only regular private accounts are supported".into());
    };
    let private_state = ring.last_included_private_state(endpoint, private_account)?;
    let signer = if direction == Direction::Deposit {
        Some(ring.signing_key(public_account)?)
    } else {
        None
    };
    let (mut policy, app) = policy(*from.value())?;
    let transfer = Transfer {
        public_account,
        private_account,
        private_state,
        identifier,
        direction,
        amount: args[offset + 2].parse()?,
    };
    let prepared = if nft {
        shielded_transfer::prepare_nft(
            &mut policy,
            &app,
            endpoint,
            transfer,
            AccountId::from_str(&args[4])?,
            now()?,
        )?
    } else if token {
        shielded_transfer::prepare_token(
            &mut policy,
            &app,
            endpoint,
            transfer,
            AccountId::from_str(&args[4])?,
            now()?,
        )?
    } else {
        shielded_transfer::prepare(&mut policy, &app, endpoint, transfer, now()?)?
    };
    eprintln!(
        "Local proving may take several minutes. Public balance changes remain visible.\nProgram source verification: not locally verified. Fees are not estimated.\n{}",
        serde_json::to_string_pretty(prepared.prompt())?
    );
    if !approve()? {
        return Err("Canceled without proving or submitting".into());
    }
    policy.decide(prepared.prompt().id, true, now()?)?;
    let proven = shielded_transfer::prove(
        &mut policy,
        &app,
        &prepared,
        endpoint,
        &keys,
        signer.as_ref(),
        now()?,
    )?;
    ring.retain_private_transfer(&proven)?;
    let hash = proven.transaction().hash();
    node.submit(proven.transaction())
        .map_err(|source| logos_wallet_lez::Error::Submission { hash, source })?;
    println!(
        "{}",
        serde_json::json!({"transaction":hash,"status":"submitted","confirmed":false,"recovery":"saved in encrypted wallet; select private account and use private-status"})
    );
    Ok(())
}
fn run(args: Vec<String>) -> Result<(), Box<dyn Error>> {
    match args.get(1).map(String::as_str) {
        Some(operation @ "private-transfer") if args.len() == 7 => {
            run_private_pair(operation, &args)?
        }
        Some(operation @ ("private-token-transfer" | "private-nft-transfer"))
            if args.len() == 8 =>
        {
            run_private_pair(operation, &args)?
        }
        Some("nft-transfer-new") if args.len() == 7 => run_nft_new_holding(&args)?,
        Some("public-status") if args.len() == 5 => {
            let password = Zeroizing::new(logos_registry_sdk::terminal::prompt_secret(
                "Wallet password: ",
            )?);
            let mut ring = Keyring::open(Path::new(&args[3]), password.as_bytes())?;
            drop(password);
            let status = ring.reconcile_public_submission(
                &public_cli_principal(),
                &args[4],
                args[2].trim_end_matches('/'),
                now()?,
            )?;
            println!("{}", serde_json::to_string(&status)?);
        }
        Some("sync-private") if (4..=5).contains(&args.len()) => {
            run_private("sync-private", &args)?
        }
        Some("private-token-initialize") if args.len() == 5 => {
            run_private("private-token-initialize", &args)?
        }
        Some(operation @ ("token-shield" | "token-unshield" | "nft-shield" | "nft-unshield"))
            if args.len() == 8 =>
        {
            run_private(operation, &args)?
        }
        Some("recover-private") if args.len() == 5 => run_private("recover-private", &args)?,
        Some(operation @ ("private-initialize" | "private-status")) if args.len() == 4 => {
            run_private(operation, &args)?
        }
        Some(operation @ ("shield" | "unshield")) if args.len() == 7 => {
            run_private(operation, &args)?
        }
        Some("new") if args.len() == 3 => {
            let password = Zeroizing::new(logos_registry_sdk::terminal::prompt_secret(
                "New wallet password: ",
            )?);
            let repeat = Zeroizing::new(logos_registry_sdk::terminal::prompt_secret(
                "Repeat wallet password: ",
            )?);
            if *password != *repeat {
                return Err("Passwords do not match".into());
            }
            Keyring::create(Path::new(&args[2]), password.as_bytes())?;
            println!(
                "{}",
                serde_json::json!({"wallet":args[2],"accounts":[],"status":"created_locally"})
            );
        }
        Some(
            operation @ ("accounts" | "add-public" | "add-private" | "import-public" | "select"
            | "rename" | "password"),
        ) if args.len()
            == match operation {
                "accounts" | "password" => 3,
                "rename" => 5,
                _ => 4,
            } =>
        {
            let password = Zeroizing::new(logos_registry_sdk::terminal::prompt_secret(
                "Wallet password: ",
            )?);
            let mut keyring = Keyring::open(Path::new(&args[2]), password.as_bytes())?;
            match operation {
                "add-public" | "add-private" => {
                    let account = if operation == "add-private" {
                        keyring.generate_private(&args[3])?
                    } else {
                        keyring.generate_public(&args[3])?
                    };
                    println!(
                        "{}",
                        serde_json::json!({"account":account,"status":"key_created_locally","chain_initialization":"not_submitted"})
                    );
                }
                "import-public" => {
                    let secret = Zeroizing::new(logos_registry_sdk::terminal::prompt_secret(
                        "LEZ private key (input hidden): ",
                    )?);
                    let key =
                        lee::PrivateKey::from_str(&secret).map_err(|_| "Invalid private key")?;
                    let account = keyring.import_public(&args[3], key.value())?;
                    println!(
                        "{}",
                        serde_json::json!({"account":account,"status":"key_imported_locally"})
                    );
                }
                "select" => keyring.select(AccountId::from_str(&args[3])?)?,
                "rename" => keyring.rename(AccountId::from_str(&args[3])?, &args[4])?,
                "password" => {
                    let next = Zeroizing::new(logos_registry_sdk::terminal::prompt_secret(
                        "New wallet password: ",
                    )?);
                    let repeat = Zeroizing::new(logos_registry_sdk::terminal::prompt_secret(
                        "Repeat wallet password: ",
                    )?);
                    if *next != *repeat {
                        return Err("Passwords do not match".into());
                    }
                    keyring.rotate_password(next.as_bytes())?;
                }
                _ => {}
            }
            if !matches!(operation, "add-public" | "add-private" | "import-public") {
                println!("{}", serde_json::json!({"accounts":keyring.accounts()?}));
            }
        }
        None | Some("help" | "--help") => {
            println!(
                "LEZ wallet CLI\n  wallet new WALLET_SQLITE\n  wallet accounts WALLET_SQLITE\n  wallet add-public WALLET_SQLITE LABEL\n  wallet add-private WALLET_SQLITE LABEL\n  wallet import-public WALLET_SQLITE LABEL\n  wallet select WALLET_SQLITE ACCOUNT_BASE58\n  wallet rename WALLET_SQLITE ACCOUNT_BASE58 LABEL\n  wallet password WALLET_SQLITE\n\n  wallet balance RPC ACCOUNT_BASE58\n  wallet private-initialize RPC WALLET_SQLITE\n  wallet private-token-initialize RPC WALLET_SQLITE DEFINITION_BASE58\n  wallet token-shield RPC WALLET_SQLITE DEFINITION_BASE58 PUBLIC_SOURCE PRIVATE_TARGET AMOUNT\n  wallet token-unshield RPC WALLET_SQLITE DEFINITION_BASE58 PRIVATE_SOURCE PUBLIC_RECIPIENT AMOUNT\n  wallet nft-shield RPC WALLET_SQLITE COLLECTION_BASE58 PUBLIC_SOURCE PRIVATE_TARGET FULL_COUNTER\n  wallet nft-unshield RPC WALLET_SQLITE COLLECTION_BASE58 PRIVATE_SOURCE PUBLIC_RECIPIENT FULL_COUNTER\n  wallet private-transfer RPC WALLET_SQLITE PRIVATE_SOURCE PRIVATE_RECIPIENT AMOUNT\n  wallet private-token-transfer RPC WALLET_SQLITE DEFINITION PRIVATE_SOURCE PRIVATE_RECIPIENT AMOUNT\n  wallet private-nft-transfer RPC WALLET_SQLITE COLLECTION PRIVATE_SOURCE PRIVATE_RECIPIENT FULL_COUNTER\n  wallet private-status RPC WALLET_SQLITE\n  wallet recover-private RPC WALLET_SQLITE TRANSACTION_HASH\n  wallet sync-private RPC WALLET_SQLITE [MAX_BLOCKS_1_TO_64]\n  wallet shield RPC WALLET_SQLITE PUBLIC_SOURCE PRIVATE_TARGET AMOUNT\n  wallet unshield RPC WALLET_SQLITE PRIVATE_SOURCE PUBLIC_RECIPIENT AMOUNT\n  wallet token-balance RPC HOLDING_BASE58\n  wallet token-initialize RPC KEY_VAULT DEFINITION_BASE58\n  wallet nft-holding RPC HOLDING_BASE58\n  wallet nft-transfer-new RPC WALLET_SQLITE COLLECTION_BASE58 SOURCE_HOLDING_BASE58 FRESH_RECIPIENT_BASE58\n  wallet public-status RPC WALLET_SQLITE REQUEST_ID\n  wallet nft-transfer RPC KEY_VAULT COLLECTION_BASE58 RECIPIENT_HOLDING_BASE58\n  wallet token-transfer RPC KEY_VAULT DEFINITION_BASE58 RECIPIENT_HOLDING_BASE58 AMOUNT_BASE_UNITS\n  wallet initialize RPC KEY_VAULT\n  wallet claim RPC KEY_VAULT AMOUNT_BASE_UNITS\n  wallet transfer RPC KEY_VAULT RECIPIENT_BASE58 AMOUNT_BASE_UNITS\n\nKEY_VAULT accepts an encrypted key file or a wallet SQLite database (selected account). Import a legacy encrypted key with registry key-import. Signing prompts require a terminal.\nUse registry status RPC HASH to check sequencer inclusion. Private operations require RISC0_PROVER=ipc and an absolute RISC0_SERVER_PATH; private-status uses the selected account. NFT FULL_COUNTER is 1 for a printed copy or the complete master print counter; initialized matching empty slots are required. Private-to-private transfers currently require two initialized accounts owned by this wallet and are under genuine proof verification. External private recipients and NFT membership proofs remain unfinished."
            );
        }
        Some("nft-holding") if args.len() == 4 => {
            let account = AccountId::from_str(&args[3])?;
            let app = AppId("local.wallet.cli".into());
            let mut policy = Policy::default();
            policy.set_grant(
                app.clone(),
                Grant {
                    accounts: [*account.value()].into_iter().collect(),
                    scopes: [Scope::NftEnumeration].into_iter().collect(),
                },
            )?;
            let wallet = NativeWallet::connect(&args[2])?;
            println!(
                "{}",
                serde_json::json!({
                    "holding": account,
                    "state": logos_wallet_lez::token::HoldingView::from(wallet.public_nft_holding(&policy, &app, *account.value())?),
                    "metadata": "not_fetched",
                    "identifier_semantics": "current holding location; not a stable printed-copy serial",
                })
            );
        }
        Some("token-balance") if args.len() == 4 => {
            let account = AccountId::from_str(&args[3])?;
            let (policy, app) = policy(*account.value())?;
            let wallet = NativeWallet::connect(&args[2])?;
            let (definition, balance) = wallet.fungible_balance(&policy, &app, *account.value())?;
            println!(
                "{}",
                serde_json::json!({"holding":account,"definition":AccountId::new(definition),"token_base_units":balance.to_string()})
            );
        }
        Some("balance") if args.len() == 4 => {
            let account = AccountId::from_str(&args[3])?;
            let (policy, app) = policy(*account.value())?;
            let wallet = NativeWallet::connect(&args[2])?;
            println!(
                "{}",
                serde_json::json!({"account":account,"native_base_units":wallet.public_balance(&policy,&app,*account.value())?.to_string(),"vault_base_units":wallet.vault_balance(&policy,&app,*account.value())?.to_string()})
            );
        }
        Some(
            operation @ ("initialize" | "claim" | "transfer" | "token-transfer"
            | "token-initialize" | "nft-transfer"),
        ) if args.len()
            == match operation {
                "initialize" => 4,
                "claim" | "token-initialize" => 5,
                "token-transfer" => 7,
                _ => 6,
            } =>
        {
            let wallet = NativeWallet::connect(&args[2])?;
            let password = Zeroizing::new(logos_registry_sdk::terminal::prompt_secret(
                "Vault password: ",
            )?);
            let mut header = [0u8; 16];
            std::fs::File::open(&args[3])?.read_exact(&mut header)?;
            let key = if &header == b"SQLite format 3\0" {
                Keyring::open(Path::new(&args[3]), password.as_bytes())?.selected_signing_key()?
            } else {
                logos_registry_sdk::publisher::read_signing_key(
                    Path::new(&args[3]),
                    password.as_bytes(),
                )?
            };
            drop(password);
            let account = AccountId::from(&PublicKey::new_from_private_key(&key));
            let (mut policy, app) = policy(*account.value())?;
            let prepared = match operation {
                "initialize" => {
                    wallet.prepare_initialize(&mut policy, &app, *account.value(), now()?)?
                }
                "claim" => wallet.prepare_claim(
                    &mut policy,
                    &app,
                    *account.value(),
                    args[4].parse()?,
                    now()?,
                )?,
                "token-initialize" => wallet.prepare_token_initialize(
                    &mut policy,
                    &app,
                    *account.value(),
                    *AccountId::from_str(&args[4])?.value(),
                    now()?,
                )?,
                "nft-transfer" => wallet.prepare_nft(
                    &mut policy,
                    &app,
                    NftTransfer {
                        from: *account.value(),
                        collection: *AccountId::from_str(&args[4])?.value(),
                        to: *AccountId::from_str(&args[5])?.value(),
                    },
                    now()?,
                )?,
                "token-transfer" => wallet.prepare_fungible(
                    &mut policy,
                    &app,
                    FungibleTransfer {
                        from: *account.value(),
                        asset: *AccountId::from_str(&args[4])?.value(),
                        to: *AccountId::from_str(&args[5])?.value(),
                        amount: args[6].parse()?,
                    },
                    now()?,
                )?,
                _ => wallet.prepare_native(
                    &mut policy,
                    &app,
                    NativeTransfer {
                        from: *account.value(),
                        to: *AccountId::from_str(&args[4])?.value(),
                        amount: args[5].parse()?,
                    },
                    now()?,
                )?,
            };
            eprintln!(
                "Requesting application: local wallet CLI\nAccount: {account}\nSequencer: {}\nOperation: {operation}\nAmounts are integer base units of the specified asset. Fees are not estimated.\nProgram source verification: not locally verified.",
                args[2]
            );
            if operation == "transfer" {
                eprintln!("Recipient: {}\nAmount: {}", args[4], args[5]);
            }
            if operation == "token-transfer" {
                eprintln!(
                    "Token definition: {}\nRecipient holding: {}\nAmount: {}",
                    args[4], args[5], args[6]
                );
            }
            if operation == "nft-transfer" {
                eprintln!(
                    "Collection: {}\nSource holding: {account}\nRecipient holding: {}",
                    args[4], args[5]
                );
            }
            if operation == "token-initialize" {
                eprintln!("Token definition: {}", args[4]);
            }
            if operation == "claim" {
                eprintln!("Amount to claim into this account: {}", args[4]);
            }
            eprintln!("{}", serde_json::to_string_pretty(prepared.prompt())?);
            if !approve()? {
                policy.decide(prepared.prompt().id, false, now()?)?;
                return Err("Canceled without signing or submitting".into());
            }
            policy.decide(prepared.prompt().id, true, now()?)?;
            let hash = wallet.execute(&mut policy, &app, &prepared, &key, now()?)?;
            println!(
                "{}",
                serde_json::json!({"transaction":hash,"status":"submitted","confirmed":false})
            );
        }
        _ => return Err("Invalid arguments; use wallet --help".into()),
    }
    Ok(())
}
fn main() {
    if let Err(e) = run(std::env::args().collect()) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
