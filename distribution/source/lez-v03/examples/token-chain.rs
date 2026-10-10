// SPDX-License-Identifier: MIT OR Apache-2.0
//! Disposable loopback fixture. Setup deliberately uses publicly known keys.
use base64::{Engine, engine::general_purpose::STANDARD};
use lee_core_v03::account::ProgramShardSelector;
use lee_v03::{
    PrivateKey, PublicKey, PublicTransaction,
    fees::FeeDeclaration,
    public_transaction::{Message, WitnessSet},
};
use logos_lez_v03::{
    AccountId, NATIVE_PROGRAM, Node, UPSTREAM_REVISION,
    outbox::{Outbox, State},
    token::{self, TokenHolding, TokenKind, TokenReader, TokenTransfer, TokenWallet},
    transfer::NativeReader,
};
use logos_wallet_policy::{Grant, Scope, principal::Principal};
use serde_json::{Value, json};
use std::{
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn key(n: u8) -> PrivateKey {
    PrivateKey::try_new([n; 32]).unwrap()
}
fn id(key: &PrivateKey) -> AccountId {
    AccountId::from_bytes(*lee_v03::AccountId::from(&PublicKey::new_from_private_key(key)).value())
}
fn up(id: AccountId) -> lee_v03::AccountId {
    lee_v03::AccountId::new(id.bytes())
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn rpc(endpoint: &str, method: &str, params: Value) -> Result<Value> {
    let value: Value = ureq::post(endpoint)
        .send_json(json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))?
        .body_mut()
        .with_config()
        .limit(1024 * 1024)
        .read_json()?;
    if value.get("error").is_some() {
        return Err(format!("fixture RPC {method}: {value}").into());
    }
    Ok(value.get("result").ok_or("missing RPC result")?.clone())
}
fn setup(
    node: &Node,
    endpoint: &str,
    payer: &PrivateKey,
    program: AccountId,
    accounts: Vec<AccountId>,
    instruction: impl borsh::BorshSerialize,
) -> Result<String> {
    let payer_id = id(payer);
    let (gas, fee) = if program == NATIVE_PROGRAM {
        (50_000, 1_000_000)
    } else {
        (8_000_000, 100_000_000)
    };
    let message = Message::try_new_with_fees(
        up(program),
        accounts
            .into_iter()
            .map(|account| ProgramShardSelector {
                account_id: up(account),
                program_account_id: up(program),
            })
            .collect(),
        vec![node.native_view(payer_id)?.nonce.into()],
        instruction,
        FeeDeclaration::new(up(payer_id), gas, 7, fee),
    )?;
    let witness = WitnessSet::for_message(&message, &[payer]);
    let tx = PublicTransaction::new(message, witness);
    let mut bytes = vec![0];
    bytes.extend(borsh::to_vec(&tx)?);
    let encoded = STANDARD.encode(bytes);
    let hash = hex::encode(tx.hash());
    assert_eq!(
        rpc(endpoint, "sendTransaction", json!([encoded]))?,
        json!(hash)
    );
    let start = Instant::now();
    loop {
        let observed = rpc(endpoint, "getTransaction", json!([hash]))?;
        if !observed.is_null() {
            assert_eq!(observed[0], json!(encoded));
            break;
        }
        if start.elapsed() > Duration::from_secs(120) {
            return Err("fixture setup transaction not included".into());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Ok(hash)
}
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("fixture-account") {
        println!("{}", id(&key(1)));
        return Ok(());
    }
    let owner_ui = args.len() == 5 && args[3] == "--owner-ui";
    let sdk_ui = args.len() == 5 && args[3] == "--sdk-ui";
    if args.len() != 3 && !(args.len() == 4 && args[3] == "--cli") && !owner_ui && !sdk_ui {
        return Err("Usage: token-chain LOOPBACK_RPC NEW_WALLET_PATH [--cli]".into());
    }
    let endpoint = &args[1];
    let uri: ureq::http::Uri = endpoint.parse()?;
    if uri.scheme_str() != Some("http")
        || uri.host() != Some("127.0.0.1")
        || uri.port_u16().is_none()
    {
        return Err("Only disposable loopback nodes accepted".into());
    }
    let node = Node::new(endpoint)?;
    node.verify_token_program()?;
    let sources = [id(&key(11)), id(&key(12)), id(&key(13))];
    let destinations = [id(&key(14)), id(&key(15)), id(&key(16))];
    let fungible = id(&key(21));
    let nft = id(&key(22));
    let metadata = id(&key(23));
    let mut setup_hashes = Vec::new();
    for source in sources {
        setup_hashes.push(setup(
            &node,
            endpoint,
            &key(1),
            NATIVE_PROGRAM,
            vec![id(&key(1)), source],
            lee_core_v03::native_token::Instruction::Transfer {
                amount: 1_000_000_000,
            },
        )?);
    }
    setup_hashes.push(setup(
        &node,
        endpoint,
        &key(1),
        token::program(),
        vec![fungible, sources[0]],
        token_core_v03::Instruction::NewFungibleDefinition {
            name: "Synthetic v0.3 fixture units".into(),
            total_supply: 1000,
        },
    )?);
    setup_hashes.push(setup(
        &node,
        endpoint,
        &key(1),
        token::program(),
        vec![nft, sources[1], metadata],
        token_core_v03::Instruction::NewDefinitionWithMetadata {
            new_definition: token_core_v03::NewTokenDefinition::NonFungible {
                name: "Synthetic v0.3 fixture NFT".into(),
                printable_supply: 7,
            },
            metadata: Box::new(token_core_v03::NewTokenMetadata {
                standard: token_core_v03::MetadataStandard::Simple,
                uri: "".into(),
                creators: "Local fixture only".into(),
            }),
        },
    )?);
    setup_hashes.push(setup(
        &node,
        endpoint,
        &key(12),
        token::program(),
        vec![sources[1], sources[2]],
        token_core_v03::Instruction::PrintNft {
            definition_id: up(nft),
        },
    )?);
    assert_eq!(
        token::holding(&node.token_view(sources[0])?)?,
        Some(TokenHolding::Fungible {
            definition_id: up(fungible),
            balance: 1000
        })
    );
    assert_eq!(
        token::holding(&node.token_view(sources[1])?)?,
        Some(TokenHolding::NftMaster {
            definition_id: up(nft),
            print_balance: 6
        })
    );
    assert_eq!(
        token::holding(&node.token_view(sources[2])?)?,
        Some(TokenHolding::NftPrintedCopy {
            definition_id: up(nft),
            owned: true
        })
    );
    eprintln!("Created genuine local v0.3 fungible, NFT master and printed-copy fixture states");
    let path = Path::new(&args[2]);
    if args.get(3).map(String::as_str) == Some("--cli") {
        let context = path.with_extension("fixture-context.json");
        std::fs::write(
            &context,
            serde_json::to_vec(
                &json!({"funded":id(&key(1)),"native_recipient":id(&key(20)),"sources":sources,"destinations":destinations,
            "fungible":fungible,"nft":nft,"token_program":token::program(),"fungible_bytes":fungible.bytes(),"nft_bytes":nft.bytes()}),
            )?,
        )?;
        let script =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/test-v03-wallet-cli.py");
        let result = std::process::Command::new("python3")
            .arg(script)
            .args(["--rpc", endpoint, "--wallet", &args[2], "--context"])
            .arg(context)
            .stderr(std::process::Stdio::inherit())
            .output()?;
        if !result.status.success() {
            return Err(format!(
                "CLI fixture failed: {}",
                String::from_utf8_lossy(&result.stdout)
            )
            .into());
        }
        let mut evidence: Value = serde_json::from_slice(&result.stdout)?;
        evidence["setup_transactions"] = json!(setup_hashes);
        evidence["adapter_revision"] = json!(UPSTREAM_REVISION);
        println!("{}", serde_json::to_string_pretty(&evidence)?);
        return Ok(());
    }
    if owner_ui || sdk_ui {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let mut store = Outbox::create(path, b"synthetic v03 Basecamp password")?;
        for (i, source) in sources.iter().enumerate() {
            assert_eq!(
                store.owner_import_public(
                    zeroize::Zeroizing::new(*key(11 + i as u8).value()),
                    [
                        "Token account",
                        "NFT master account",
                        "Printed copy account"
                    ][i]
                )?,
                *source
            );
        }
        drop(store);
        let kinds = ["fungible", "nft-master", "nft-copy"];
        let mut before = Vec::new();
        let mut recipient_before = Vec::new();
        let mut transfers = Vec::new();
        for i in 0..3 {
            before.push(node.native_view(sources[i])?);
            recipient_before.push(node.native_view(destinations[i])?);
            transfers.push(json!({"kind":kinds[i],"from":sources[i],"to":destinations[i],"definition":if i==0{fungible}else{nft},"amount":(["123","6","1"][i]),"gas_limit":"8000000","tip":"7","max_fee":"100000000","native_before":before[i].native_balance()?.to_string()}));
        }
        let context = path.with_extension("owner-context.json");
        std::fs::write(
            &context,
            serde_json::to_vec(&json!({"transfers":transfers}))?,
        )?;
        let child = std::process::Command::new("python3")
            .arg(root.join(if sdk_ui {
                "scripts/test-basecamp-v03-sdk.py"
            } else {
                "scripts/test-basecamp-v03-owner.py"
            }))
            .args([
                "--basecamp",
                &args[4],
                "--rpc",
                endpoint,
                "--seed-wallet",
                &args[2],
                "--context",
            ])
            .arg(context)
            .env("TMPDIR", root.join(".tmp"))
            .stderr(std::process::Stdio::inherit())
            .output()?;
        eprint!("{}", String::from_utf8_lossy(&child.stdout));
        if !child.status.success() {
            return Err("Basecamp owner token form fixture failed".into());
        }
        let evidence: Value = serde_json::from_slice(&std::fs::read(root.join(if sdk_ui {
            "evidence/basecamp-v03-sdk-tokens.json"
        } else {
            "evidence/basecamp-v03-owner-tokens.json"
        }))?)?;
        assert_eq!(evidence["result"], "passed");
        let mut results = Vec::new();
        for i in 0..3 {
            let after = node.native_view(sources[i])?;
            let recipient_after = node.native_view(destinations[i])?;
            assert_eq!(after.nonce, before[i].nonce + 1);
            assert_eq!(recipient_after.nonce, recipient_before[i].nonce);
            assert_eq!(
                recipient_after.native_balance()?,
                recipient_before[i].native_balance()?
            );
            let fee = before[i]
                .native_balance()?
                .checked_sub(after.native_balance()?)
                .ok_or("native balance increased")?;
            assert!(fee > 0 && fee <= 100_000_000);
            let definition = if i == 0 { fungible } else { nft };
            let (expected_sender, expected_recipient) = match i {
                0 => (
                    TokenHolding::Fungible {
                        definition_id: up(definition),
                        balance: 877,
                    },
                    TokenHolding::Fungible {
                        definition_id: up(definition),
                        balance: 123,
                    },
                ),
                1 => (
                    TokenHolding::NftMaster {
                        definition_id: up(definition),
                        print_balance: 0,
                    },
                    TokenHolding::NftMaster {
                        definition_id: up(definition),
                        print_balance: 6,
                    },
                ),
                _ => (
                    TokenHolding::NftPrintedCopy {
                        definition_id: up(definition),
                        owned: false,
                    },
                    TokenHolding::NftPrintedCopy {
                        definition_id: up(definition),
                        owned: true,
                    },
                ),
            };
            assert_eq!(
                token::holding(&node.token_view(sources[i])?)?.as_ref(),
                Some(&expected_sender)
            );
            assert_eq!(
                token::holding(&node.token_view(destinations[i])?)?.as_ref(),
                Some(&expected_recipient)
            );
            assert_eq!(
                evidence["after"][i]["inventory"]["native_balance"],
                after.native_balance()?.to_string()
            );
            results.push(json!({"kind":kinds[i],"sender":expected_sender,"recipient":expected_recipient,"observed_fee_debit":fee.to_string(),"approved_cap":"100000000","sender_nonce_advanced_once":true,"recipient_nonce_unchanged":true,"recipient_native_balance_unchanged":true}));
        }
        println!(
            "{}",
            serde_json::to_string(
                &json!({"result":"passed","basecamp":evidence,"transfers":results,"setup_transactions":setup_hashes,"adapter_revision":UPSTREAM_REVISION,"scope":if sdk_ui {"Actual Basecamp third-party QML SDK scoped reads and public membership queries, separate production consent UI for fungible/master/copy transfers, real local chain balances, ownership, fees and encrypted restart. No private proofs, public-testnet writes, release or adoption."} else {"Actual Basecamp production QML owner fungible/master/copy send forms, synthetic local reference-token execution, observed fees and encrypted restart. No private proofs, public-testnet writes, catalog publication or adoption."}})
            )?
        );
        return Ok(());
    }
    let password = b"disposable v03 token fixture password";
    let principal = Principal::LocalCli;
    let mut store = Outbox::create(path, password)?;
    for (i, source) in sources.iter().enumerate() {
        assert_eq!(
            store.owner_import_public(
                zeroize::Zeroizing::new(*key(11 + i as u8).value()),
                "Synthetic token fixture sender"
            )?,
            *source
        );
    }
    store.owner_set_grant(
        &principal,
        Some(Grant {
            accounts: sources.iter().map(|a| a.bytes()).collect(),
            scopes: [Scope::Accounts, Scope::Transactions].into(),
        }),
    )?;
    drop(store);
    let mut store = Outbox::open(path, password)?;
    assert_eq!(store.accounts_for(&principal)?.len(), 3);
    let wallet = TokenWallet::new(Node::new(endpoint)?, endpoint)?;
    let mut results = Vec::new();
    for (i, kind) in [
        TokenKind::Fungible,
        TokenKind::NftMaster,
        TokenKind::NftPrintedCopy,
    ]
    .into_iter()
    .enumerate()
    {
        eprintln!("Preparing approved {kind:?} transfer with persisted v0.3 key");
        let from = sources[i];
        let to = destinations[i];
        let definition = if i == 0 { fungible } else { nft };
        let amount = [123, 6, 1][i];
        let before = node.native_view(from)?;
        let recipient_before = node.native_view(to)?;
        assert!(token::holding(&node.token_view(to)?)?.is_none());
        let transfer = TokenTransfer {
            from,
            to,
            definition,
            kind,
            amount,
            gas_limit: 8_000_000,
            tip: 7,
            max_fee: 100_000_000,
        };
        let prepared = store.prepare_token(&principal, &wallet, transfer, now())?;
        let request_id = format!("{:032x}", i + 1);
        assert!(
            store
                .execute_token(&principal, &request_id, &wallet, &node, &prepared, now())
                .is_err()
        );
        store.owner_decide(prepared.prompt().id, true, now())?;
        let status =
            store.execute_token(&principal, &request_id, &wallet, &node, &prepared, now())?;
        assert_eq!(status.state, State::Submitted);
        assert!(
            store
                .execute_token(&principal, &request_id, &wallet, &node, &prepared, now())
                .is_err()
        );
        drop(store);
        store = Outbox::open(path, password)?;
        assert_eq!(store.status(&principal, &request_id)?, status);
        let start = Instant::now();
        let included = loop {
            let status = store.reconcile(&principal, &request_id, &node, now())?;
            if status.state == State::IncludedBySequencer {
                break status;
            }
            if start.elapsed() > Duration::from_secs(120) {
                return Err("token transfer not observed included".into());
            }
            std::thread::sleep(Duration::from_millis(500));
        };
        let after = node.native_view(from)?;
        let recipient_after = node.native_view(to)?;
        assert_eq!(after.nonce, before.nonce + 1);
        assert_eq!(recipient_after.nonce, recipient_before.nonce);
        assert_eq!(
            recipient_after.native_balance()?,
            recipient_before.native_balance()?
        );
        let fee = before
            .native_balance()?
            .checked_sub(after.native_balance()?)
            .ok_or("token sender native balance increased")?;
        assert!(fee > 0 && fee <= transfer.max_fee);
        let sender = token::holding(&node.token_view(from)?)?.ok_or("missing sender holding")?;
        let recipient =
            token::holding(&node.token_view(to)?)?.ok_or("missing auto-initialized recipient")?;
        let (expected_sender, expected_recipient) = match kind {
            TokenKind::Fungible => (
                TokenHolding::Fungible {
                    definition_id: up(definition),
                    balance: 877,
                },
                TokenHolding::Fungible {
                    definition_id: up(definition),
                    balance: 123,
                },
            ),
            TokenKind::NftMaster => (
                TokenHolding::NftMaster {
                    definition_id: up(definition),
                    print_balance: 0,
                },
                TokenHolding::NftMaster {
                    definition_id: up(definition),
                    print_balance: 6,
                },
            ),
            TokenKind::NftPrintedCopy => (
                TokenHolding::NftPrintedCopy {
                    definition_id: up(definition),
                    owned: false,
                },
                TokenHolding::NftPrintedCopy {
                    definition_id: up(definition),
                    owned: true,
                },
            ),
        };
        assert_eq!(sender, expected_sender);
        assert_eq!(recipient, expected_recipient);
        drop(store);
        store = Outbox::open(path, password)?;
        assert_eq!(store.status(&principal, &request_id)?, included);
        results.push(json!({"kind":format!("{kind:?}"),"transaction":included,"sender":sender,"recipient":recipient,"from":from,"to":to,
            "observed_fee_debit":fee.to_string(),"approved_fee_cap":transfer.max_fee.to_string(),"approval_one_use":true,"stored_key_signing":true,
            "sender_nonce_advanced_once":true,"recipient_nonce_unchanged":true,"recipient_native_balance_unchanged":true,"recipient_empty_shard_initialized":true,"restart_preserved_transaction":true}));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"result":"passed","adapter_revision":UPSTREAM_REVISION,"token_image":token::IMAGE,"setup_transactions":setup_hashes,"transfers":results,
        "scope":"Synthetic local v0.3 sequencer public fungible, master and printed-copy transfers with actual guest execution, observed fees and restart recovery. No private proofs, public-testnet writes, Basecamp integration, stable NFT serials or adoption."})
        )?
    );
    Ok(())
}
