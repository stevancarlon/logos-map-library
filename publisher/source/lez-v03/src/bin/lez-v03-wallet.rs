// SPDX-License-Identifier: MIT OR Apache-2.0
//! Trusted terminal owner, with live TTY consent. Not a Basecamp dApp dispatcher.
// Reuse the protocol-independent hidden-input shim without pulling the v0.2 SDK.
#[path = "../../../registry-sdk/src/terminal.rs"]
mod terminal;
use logos_lez_v03::{
    AccountId, Node,
    outbox::{Outbox, Status},
    shielded::{Direction, NativeOperation, PrivateIdentity},
    token::{self, TokenHolding, TokenKind, TokenReader, TokenTransfer, TokenWallet},
    transfer::{NativeReader, NativeTransfer, Wallet},
};
use logos_wallet_policy::{Effect, Prompt, Request, principal::Principal};
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use std::{
    error::Error,
    io::{BufRead, Read, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
const HELP: &str = "v0.3 wallet (existing v0.2 wallets are not imported)
  create WALLET
  accounts WALLET
  new-public WALLET LABEL
  import-public WALLET LABEL
  private-accounts WALLET
  new-private WALLET LABEL
  import-private WALLET LABEL
  shield-native WALLET RPC PUBLIC_ACCOUNT PRIVATE_ACCOUNT AMOUNT
  unshield-native WALLET RPC PRIVATE_ACCOUNT PUBLIC_ACCOUNT AMOUNT
  private-activity WALLET
  private-status WALLET REQUEST_ID
  private-reconcile WALLET RPC REQUEST_ID
  rename WALLET ACCOUNT LABEL
  select WALLET ACCOUNT
  rotate-password WALLET
  native-balance RPC ACCOUNT
  token-balance RPC ACCOUNT
  send-native WALLET RPC FROM TO AMOUNT GAS_LIMIT TIP MAX_FEE
  send-token WALLET RPC FROM TO DEFINITION KIND AMOUNT GAS_LIMIT TIP MAX_FEE
  activity WALLET
  status WALLET REQUEST_ID
  reconcile WALLET RPC REQUEST_ID
KIND: fungible | nft-copy | nft-master. All amounts are integer base units.
Passwords and import keys are read from a hidden live-terminal prompt.
Every transfer needs a separate APPROVE; there is no --yes or automatic retry.";
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn secret(prompt: &str) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(terminal::prompt_secret(prompt)?))
}
fn new_password() -> Result<Zeroizing<String>> {
    let password = secret("New wallet password: ")?;
    let repeated = secret("Repeat wallet password: ")?;
    if password.is_empty() || password.len() > 4096 || *password != *repeated {
        return Err("Passwords must match and contain 1–4096 bytes".into());
    }
    Ok(password)
}
fn open(path: &str) -> Result<Outbox> {
    let password = secret("Wallet password: ")?;
    Ok(Outbox::open(Path::new(path), password.as_bytes())?)
}
fn output(value: impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string(&value)?);
    Ok(())
}
fn status(value: Status) -> Result<()> {
    output(
        json!({"transaction":value,"execution_outcome":"unknown","note":"Sequencer inclusion alone does not prove successful execution or independent finality."}),
    )
}
fn review(prompt: &Prompt, private: bool) -> Result<bool> {
    let Request::Transaction(request) = &prompt.request else {
        return Err("Expected a transaction review".into());
    };
    // Write the complete review to the same live TTY as the decision. Redirected
    // stdout cannot hide the action from the approving operator.
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")?;
    writeln!(
        tty,
        "\n{} v0.3 transaction\nNetwork: {}\nSigning account: {}",
        if private { "Private" } else { "Public" },
        request.network,
        AccountId::from_bytes(request.account)
    )?;
    for effect in &request.effects {
        match effect {
            Effect::NativeTransfer {
                amount,
                destination,
            } => writeln!(
                tty,
                "Send {amount} native base units to {}",
                AccountId::from_bytes(*destination)
            )?,
            Effect::TokenTransfer {
                asset,
                amount,
                destination,
            } => writeln!(
                tty,
                "Send {amount} token base units of {} to {}",
                AccountId::from_bytes(*asset),
                AccountId::from_bytes(*destination)
            )?,
            Effect::NftTransfer {
                collection,
                token,
                destination,
            } => writeln!(
                tty,
                "Send one printed NFT from holding {} in collection {} to {}. The holding address is not a stable token serial.",
                AccountId::from_bytes(*token),
                AccountId::from_bytes(*collection),
                AccountId::from_bytes(*destination)
            )?,
            Effect::ContractCall {
                instruction,
                explanation,
                ..
            } => writeln!(tty, "{instruction}: {explanation}")?,
            _ => return Err("Unsupported review effect; refusing to request approval".into()),
        }
    }
    if private {
        writeln!(
            tty,
            "Local proving may take considerable time. Submission does not confirm the private opening; reconcile this request before spending again."
        )?;
    } else {
        writeln!(
            tty,
            "Fees may still be charged if execution fails after submission."
        )?;
    }
    write!(
        tty,
        "Type APPROVE for this exact request, or anything else to cancel: "
    )?;
    tty.flush()?;
    let mut answer = String::new();
    std::io::BufReader::new(tty)
        .take(128)
        .read_line(&mut answer)?;
    Ok(answer.trim() == "APPROVE")
}
fn request_id() -> Result<String> {
    let mut id = [0; 16];
    OsRng
        .try_fill_bytes(&mut id)
        .map_err(|_| "OS randomness unavailable")?;
    let id = hex::encode(id);
    println!("Request ID: {id}");
    std::io::stdout().flush()?;
    Ok(id)
}
fn holding_json(holding: Option<TokenHolding>) -> Value {
    match holding {
        None => json!({"kind":"empty"}),
        Some(TokenHolding::Fungible {
            definition_id,
            balance,
        }) => {
            json!({"kind":"fungible","definition":definition_id.to_string(),"balance":balance.to_string()})
        }
        Some(TokenHolding::NftMaster {
            definition_id,
            print_balance,
        }) => {
            json!({"kind":"nft-master","definition":definition_id.to_string(),"print_counter":print_balance.to_string(),"owned":print_balance>0,"remaining_print_rights":print_balance.saturating_sub(1).to_string()})
        }
        Some(TokenHolding::NftPrintedCopy {
            definition_id,
            owned,
        }) => json!({"kind":"nft-copy","definition":definition_id.to_string(),"owned":owned}),
    }
}
fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let parts: Vec<&str> = args.iter().map(String::as_str).collect();
    match parts.as_slice() {
        [] | ["--help"] | ["help"] => {
            println!("{HELP}");
            Ok(())
        }
        ["create", path] => {
            let password = new_password()?;
            Outbox::create(Path::new(path), password.as_bytes())?;
            output(json!({"created":true,"protocol":"v0.3","accounts":[]}))
        }
        ["accounts", path] => output(open(path)?.owner_accounts()?),
        ["private-accounts", path] => output(open(path)?.owner_private_accounts()?),
        ["new-private", path, label] => output(
            json!({"account":open(path)?.owner_create_private(label)?,"privacy":"private","protocol":"v0.3"}),
        ),
        ["import-private", path, label] => {
            let mut store = open(path)?;
            let raw = secret("v0.3 spending seed hex (input hidden): ")?;
            let identifier = secret("v0.3 opaque identifier hex (input hidden): ")?;
            let mut seed = Zeroizing::new([0; 32]);
            let mut identifier_bytes = Zeroizing::new([0; 32]);
            if raw.len() != 64
                || identifier.len() != 64
                || hex::decode_to_slice(raw.as_bytes(), &mut *seed).is_err()
                || hex::decode_to_slice(identifier.as_bytes(), &mut *identifier_bytes).is_err()
            {
                return Err(
                    "Seed and identifier must each contain exactly 64 hexadecimal characters"
                        .into(),
                );
            }
            output(
                json!({"account":store.owner_import_private(PrivateIdentity::from_seed(seed,*identifier_bytes),label)?,"privacy":"private","protocol":"v0.3","note":"Only the identity was imported; chain history and existing openings were not recovered."}),
            )
        }
        [
            command @ ("shield-native" | "unshield-native"),
            path,
            rpc,
            from,
            to,
            amount,
        ] => {
            let (direction, public, private) = if *command == "shield-native" {
                (Direction::Deposit, *from, *to)
            } else {
                (Direction::Withdrawal, *to, *from)
            };
            let operation = NativeOperation {
                public_account: public.parse()?,
                direction,
                amount: amount.parse()?,
            };
            let node = Node::new(rpc)?;
            let mut store = open(path)?;
            let prepared =
                store.owner_prepare_private_native(&node, private.parse()?, operation, now()?)?;
            let approved = review(prepared.prompt(), true)?;
            store.owner_decide(prepared.prompt().id, approved, now()?)?;
            if !approved {
                return output(json!({"cancelled":true}));
            }
            let id = request_id()?;
            output(store.owner_execute_private_native(&id, &node, &prepared, now()?)?)
        }
        ["private-activity", path] => output(open(path)?.owner_private_activity()?),
        ["private-status", path, id] => output(open(path)?.owner_private_status(id)?),
        ["private-reconcile", path, rpc, id] => {
            output(open(path)?.owner_reconcile_private(id, &Node::new(rpc)?, now()?)?)
        }
        ["new-public", path, label] => {
            let mut store = open(path)?;
            output(
                json!({"account":store.owner_create_public(label)?,"privacy":"public","protocol":"v0.3"}),
            )
        }
        ["import-public", path, label] => {
            let mut store = open(path)?;
            let raw = secret("Public-account private key hex (input hidden): ")?;
            let mut key = Zeroizing::new([0; 32]);
            if raw.len() != 64 || hex::decode_to_slice(raw.as_bytes(), &mut *key).is_err() {
                return Err("Expected exactly 64 hexadecimal key characters".into());
            }
            output(
                json!({"account":store.owner_import_public(key,label)?,"privacy":"public","protocol":"v0.3"}),
            )
        }
        ["select", path, account] => {
            let account = account.parse()?;
            open(path)?.owner_select(account)?;
            output(json!({"selected":account}))
        }
        ["rename", path, account, label] => {
            let account = account.parse()?;
            open(path)?.owner_rename(account, label)?;
            output(json!({"renamed":account}))
        }
        ["rotate-password", path] => {
            let current = secret("Current wallet password: ")?;
            let mut store = Outbox::open(Path::new(path), current.as_bytes())?;
            let new = new_password()?;
            store.owner_rotate_password(current.as_bytes(), new.as_bytes())?;
            output(json!({"password_changed":true}))
        }
        ["native-balance", rpc, account] => {
            let account: AccountId = account.parse()?;
            let view = Node::new(rpc)?.native_view(account)?;
            output(
                json!({"account":account,"nonce":view.nonce.to_string(),"native_balance":view.native_balance()?.to_string(),"scope":"node observation"}),
            )
        }
        ["token-balance", rpc, account] => {
            let account: AccountId = account.parse()?;
            let node = Node::new(rpc)?;
            node.verify_token_program()?;
            let view = node.token_view(account)?;
            output(
                json!({"account":account,"nonce":view.nonce.to_string(),"holding":holding_json(token::holding(&view)?),"scope":"public node observation; no metadata/media fetched"}),
            )
        }
        [
            "send-native",
            path,
            rpc,
            from,
            to,
            amount,
            gas,
            tip,
            max_fee,
        ] => {
            let transfer = NativeTransfer {
                from: from.parse()?,
                to: to.parse()?,
                amount: amount.parse()?,
                gas_limit: gas.parse()?,
                tip: tip.parse()?,
                max_fee: max_fee.parse()?,
            };
            let node = Node::new(rpc)?;
            let wallet = Wallet::new(Node::new(rpc)?, rpc)?;
            let mut store = open(path)?;
            store.owner_allow_local_cli_account(transfer.from)?;
            let prepared = store.prepare_native(&Principal::LocalCli, &wallet, transfer, now()?)?;
            if !review(prepared.prompt(), false)? {
                return output(json!({"cancelled":true}));
            }
            store.owner_decide(prepared.prompt().id, true, now()?)?;
            let id = request_id()?;
            status(store.execute_native(
                &Principal::LocalCli,
                &id,
                &wallet,
                &node,
                &prepared,
                now()?,
            )?)
        }
        [
            "send-token",
            path,
            rpc,
            from,
            to,
            definition,
            kind,
            amount,
            gas,
            tip,
            max_fee,
        ] => {
            let kind = match *kind {
                "fungible" => TokenKind::Fungible,
                "nft-copy" => TokenKind::NftPrintedCopy,
                "nft-master" => TokenKind::NftMaster,
                _ => return Err("KIND must be fungible, nft-copy or nft-master".into()),
            };
            let transfer = TokenTransfer {
                from: from.parse()?,
                to: to.parse()?,
                definition: definition.parse()?,
                kind,
                amount: amount.parse()?,
                gas_limit: gas.parse()?,
                tip: tip.parse()?,
                max_fee: max_fee.parse()?,
            };
            let node = Node::new(rpc)?;
            let wallet = TokenWallet::new(Node::new(rpc)?, rpc)?;
            let mut store = open(path)?;
            store.owner_allow_local_cli_account(transfer.from)?;
            let prepared = store.prepare_token(&Principal::LocalCli, &wallet, transfer, now()?)?;
            if !review(prepared.prompt(), false)? {
                return output(json!({"cancelled":true}));
            }
            store.owner_decide(prepared.prompt().id, true, now()?)?;
            let id = request_id()?;
            status(store.execute_token(
                &Principal::LocalCli,
                &id,
                &wallet,
                &node,
                &prepared,
                now()?,
            )?)
        }
        ["activity", path] => output(open(path)?.activity_for(&Principal::LocalCli)?),
        ["status", path, id] => status(open(path)?.status(&Principal::LocalCli, id)?),
        ["reconcile", path, rpc, id] => {
            let node = Node::new(rpc)?;
            status(open(path)?.reconcile(&Principal::LocalCli, id, &node, now()?)?)
        }
        _ => Err(format!("Invalid command or argument count.\n{HELP}").into()),
    }
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
