// SPDX-License-Identifier: MIT OR Apache-2.0
//! Interactive map publisher. Passwords and approval are accepted only from a terminal.
use lee_core_v03::account::AccountId;
use lee_v03::{PrivateKey, PublicKey, fees::FeeDeclaration};
use logos_maps_v03_publisher::{Publisher, Status, prepare};
#[cfg(feature = "hosting")]
mod hosting;
use logos_maps_v03_sdk::{Instruction, Registry, Snapshot, rpc::Node};
use logos_wallet_policy::vault;
use rand_core::{OsRng, RngCore};
use std::{
    error::Error,
    fs::File,
    io::{BufRead, IsTerminal, Read, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
const HELP: &str = "maps-publish key-create NEW_KEY_VAULT
maps-publish key-import NEW_KEY_VAULT
maps-publish outbox-create NEW_SQLITE
maps-publish history SQLITE
maps-publish reconcile RPC SQLITE HASH
maps-publish publish-all RPC PROGRAM KEY_VAULT SQLITE SNAPSHOTS_JSON_FILE GAS_LIMIT MAX_FEE TIP
maps-publish host-local|host-fetch RPC PROGRAM STORAGE_API REGION YYYYMMDD PBF MAX_BYTES NEW_RECEIPT KEY_VAULT SQLITE GAS_LIMIT MAX_FEE TIP
maps-publish host-bulk RPC PROGRAM STORAGE_API ITEMS_JSON_FILE MAX_BYTES NEW_RECEIPT KEY_VAULT SQLITE GAS_LIMIT MAX_FEE TIP
maps-publish register-next RPC PROGRAM KEY_VAULT SQLITE SNAPSHOTS_JSON_FILE GAS_LIMIT MAX_FEE TIP
maps-publish register RPC PROGRAM KEY_VAULT SQLITE SNAPSHOTS_JSON_FILE GAS_LIMIT MAX_FEE TIP
maps-publish write RPC PROGRAM KEY_VAULT SQLITE INSTRUCTION_JSON_FILE GAS_LIMIT MAX_FEE TIP

Host commands require the hosting build feature. They save uploaded snapshots
to a new receipt before signing. publish-all resumes a receipt without reuploading.
Every write needs a separate approval; cancellation preserves the receipt/outbox.
Use register-next for 1–72 selected regions: review one initialization, page creation
or registration step per invocation. Reconcile the saved hash, then run it again;
matching records by this signer are skipped. Completion comes from registry state.
Use register for 1–8 stored snapshots within one registry page. Use write for the
SPEL-generated Initialize/CreatePage/RegisterBatch instruction JSON. Each write
requires exact review-digest approval. Fees are explicit caps in native units,
not a prediction of the final fee. Review includes the current/next-block fee
reserve and payer balance, both rechecked before signing. No automatic page
creation, retries, or refreshed registration.
Passwords/private keys must never be provided in command arguments.
";
fn terminal() -> Result<()> {
    if !std::io::stdin().is_terminal() {
        return Err("Interactive terminal required".into());
    }
    Ok(())
}
// Disable echo before rpassword writes its prompt. Its own reader subsequently
// configures raw input and restores this already-hidden state; our guard finally
// restores the original terminal attributes, including on ordinary errors.
#[cfg(unix)]
struct HiddenTerminal {
    terminal: File,
    original: libc::termios,
}
#[cfg(unix)]
impl HiddenTerminal {
    fn new() -> std::io::Result<Self> {
        use std::os::fd::AsRawFd;
        let terminal = File::options().read(true).write(true).open("/dev/tty")?;
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: the file is live and tcgetattr initializes the output on success.
        if unsafe { libc::tcgetattr(terminal.as_raw_fd(), original.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: tcgetattr succeeded above.
        let original = unsafe { original.assume_init() };
        let mut hidden = original;
        hidden.c_lflag &= !(libc::ECHO | libc::ECHONL);
        // SAFETY: valid terminal descriptor and initialized termios value.
        if unsafe { libc::tcsetattr(terminal.as_raw_fd(), libc::TCSANOW, &hidden) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { terminal, original })
    }
}
#[cfg(unix)]
impl Drop for HiddenTerminal {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        // SAFETY: the owned descriptor stays live through this drop.
        unsafe {
            libc::tcsetattr(self.terminal.as_raw_fd(), libc::TCSANOW, &self.original);
        }
    }
}
fn password(prompt: &str) -> Result<Zeroizing<String>> {
    terminal()?;
    #[cfg(unix)]
    let _hidden = HiddenTerminal::new()?;
    let value = Zeroizing::new(rpassword::prompt_password(prompt)?);
    if value.is_empty() || value.len() > 1024 {
        return Err("Password must contain 1–1024 bytes".into());
    }
    Ok(value)
}
fn new_password() -> Result<Zeroizing<String>> {
    let value = password("New password: ")?;
    let repeated = password("Repeat password: ")?;
    if *value != *repeated {
        return Err("Passwords do not match".into());
    }
    Ok(value)
}
fn account(key: &PrivateKey) -> AccountId {
    AccountId::from(&PublicKey::new_from_private_key(key))
}
fn bounded(path: &str) -> Result<Vec<u8>> {
    let mut bytes = vec![];
    File::open(path)?.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("Input JSON exceeds 64 KiB".into());
    }
    Ok(bytes)
}
fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
struct SigningSession {
    key: PrivateKey,
    password: Zeroizing<String>,
    publisher: Publisher,
}
fn unlock(key_path: &str, outbox_path: &str) -> Result<SigningSession> {
    let pass = password("Key vault password: ")?;
    let payload = vault::read_file(Path::new(key_path), pass.as_bytes())?;
    if payload.len() != 40 || &payload[..8] != b"REGKEY01" {
        return Err("Not a registry signing-key vault".into());
    }
    let seed = Zeroizing::new(<[u8; 32]>::try_from(&payload[8..])?);
    let key = PrivateKey::try_new(*seed)?;
    drop(seed);
    drop(payload);
    drop(pass);
    let outbox_password = password("Outbox password: ")?;
    let publisher = Publisher::open(Path::new(outbox_path))?;
    // Authenticate the outbox before doing network work or asking for approval.
    publisher.submissions(outbox_password.as_bytes())?;

    Ok(SigningSession {
        key,
        password: outbox_password,
        publisher,
    })
}

fn approve_instruction(
    registry: &Registry<Node>,
    session: &mut SigningSession,
    instruction: Instruction,
    fee: FeeDeclaration,
) -> Result<serde_json::Value> {
    let proposal = prepare(registry, account(&session.key), instruction, fee, now()?)?;
    let mut review = serde_json::to_value(proposal.review())?;
    review.as_object_mut().unwrap().remove("message_borsh_hex");
    if let Some(raw) = review
        .pointer("/instruction/RegisterBatch/snapshots_json")
        .and_then(|v| v.as_str())
    {
        let snapshots: serde_json::Value = serde_json::from_str(raw)?;
        review["snapshots"] = snapshots;
    }
    eprintln!(
        "MAP REGISTRATION REVIEW\n{}",
        serde_json::to_string_pretty(&review)?
    );
    eprint!(
        "Type APPROVE {} to sign and submit once; anything else cancels: ",
        proposal.review().digest
    );
    std::io::stderr().flush()?;
    let mut approval = String::new();
    let stdin = std::io::stdin();
    std::io::BufReader::new(stdin.lock().take(256)).read_line(&mut approval)?;
    if !approval.ends_with('\n')
        || approval.len() >= 256
        || approval.trim() != format!("APPROVE {}", proposal.review().digest)
    {
        return Ok(serde_json::json!({"status":"canceled","submitted":false}));
    }
    Ok(serde_json::to_value(session.publisher.approve(
        session.password.as_bytes(),
        registry,
        proposal,
        &session.key,
        now()?,
    )?)?)
}
fn publish_all(
    registry: &Registry<Node>,
    session: &mut SigningSession,
    snapshots: &[Snapshot],
    gas: &str,
    cap: &str,
    tip: &str,
) -> Result<serde_json::Value> {
    let author = account(&session.key);
    let gas: u64 = gas.parse()?;
    let cap: u128 = cap.parse()?;
    let tip: u64 = tip.parse()?;
    let mut hashes = vec![];
    while let Some(instruction) = registry.next_registration(author, snapshots, now()?, 4096)? {
        if hashes.len() >= 32 {
            return Err(
                "Too many concurrent registry changes; resume from the saved receipt".into(),
            );
        }
        let expected = serde_json::to_value(&instruction)?;
        let row = approve_instruction(
            registry,
            session,
            instruction,
            FeeDeclaration::new(author, gas, tip, cap),
        )?;
        let Some(hash) = row["hash"].as_str() else {
            return Ok(
                serde_json::json!({"status":"canceled","complete":false,"submitted":!hashes.is_empty(),"transactions":hashes}),
            );
        };
        hashes.push(hash.to_owned());
        eprintln!(
            "Saved transaction {hash}; checking exact observation. Do not resubmit an uncertain hash."
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            if session
                .publisher
                .reconcile(session.password.as_bytes(), &registry.reader, hash)?
                .status
                == Status::Observed
            {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "Observation pending for {hash}; use reconcile before resuming"
                )
                .into());
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        // Observation is not execution: check the exact expected registry effect.
        if expected == "Initialize" {
            registry.catalog()?;
        } else if let Some(page) = expected.get("CreatePage") {
            if !registry.page_exists(page["number"].as_u64().ok_or("Invalid page review")?)? {
                return Err("Page creation was not applied; inspect the saved transaction".into());
            }
        } else if let Some(batch) = expected.get("RegisterBatch") {
            let page = registry.query(
                batch["number"].as_u64().ok_or("Invalid page review")?,
                &logos_maps_v03_sdk::Filter::default(),
            )?;
            let values: Vec<Snapshot> = serde_json::from_str(
                batch["snapshots_json"]
                    .as_str()
                    .ok_or("Invalid snapshot review")?,
            )?;
            let count = batch["expected_count"]
                .as_u64()
                .ok_or("Invalid count review")?;
            let timestamp = batch["timestamp"]
                .as_u64()
                .ok_or("Invalid timestamp review")?;
            for (i, snapshot) in values.iter().enumerate() {
                if !page.records.iter().any(|r| {
                    &r.snapshot == snapshot
                        && r.ordinal == count + i as u64
                        && r.timestamp == timestamp
                        && r.registrant.as_slice() == author.as_ref()
                }) {
                    return Err("Registration was not applied as reviewed; inspect the saved transaction before resuming".into());
                }
            }
        }
    }
    Ok(
        serde_json::json!({"status":"registered","complete":true,"verification":"matching_registry_records_by_author","snapshots":snapshots.len(),"transactions":hashes}),
    )
}
fn run(a: &[String]) -> Result<serde_json::Value> {
    match a.get(1).map(String::as_str) {
        Some("key-create" | "key-import") if a.len() == 3 => {
            terminal()?;
            let mut seed = Zeroizing::new([0u8; 32]);
            if a[1] == "key-import" {
                let secret = password("Private key (64 hex characters; hidden): ")?;
                hex::decode_to_slice(secret.trim(), seed.as_mut())?;
            } else {
                OsRng
                    .try_fill_bytes(seed.as_mut())
                    .map_err(|_| "Random source unavailable")?;
            }
            let key = PrivateKey::try_new(*seed)?;
            let pass = new_password()?;
            let mut payload = Zeroizing::new(Vec::from(b"REGKEY01".as_slice()));
            payload.extend_from_slice(seed.as_ref());
            vault::create_file(Path::new(&a[2]), pass.as_bytes(), &payload)?;
            Ok(serde_json::json!({"account":account(&key).to_string(),"vault":a[2]}))
        }
        Some("outbox-create") if a.len() == 3 => {
            let pass = new_password()?;
            Publisher::create(Path::new(&a[2]), pass.as_bytes())?;
            Ok(serde_json::json!({"created":a[2]}))
        }
        Some("history") if a.len() == 3 => {
            let pass = password("Outbox password: ")?;
            Ok(serde_json::to_value(
                Publisher::open(Path::new(&a[2]))?.submissions(pass.as_bytes())?,
            )?)
        }
        Some("reconcile") if a.len() == 5 => {
            let node = Node::new(&a[2])?;
            let pass = password("Outbox password: ")?;
            Ok(serde_json::to_value(
                Publisher::open(Path::new(&a[3]))?.reconcile(pass.as_bytes(), &node, &a[4])?,
            )?)
        }
        Some("publish-all" | "register-next" | "register" | "write") if a.len() == 10 => {
            terminal()?;
            let registry = Registry {
                reader: Node::new(&a[2])?,
                program: a[3].parse()?,
            };
            let input = bounded(&a[6])?;
            let mut session = unlock(&a[4], &a[5])?;
            let author = account(&session.key);
            if a[1] == "publish-all" {
                let snapshots: Vec<Snapshot> = serde_json::from_slice(&input)?;
                return publish_all(&registry, &mut session, &snapshots, &a[7], &a[8], &a[9]);
            }
            let instruction = if a[1] == "register-next" {
                let snapshots: Vec<Snapshot> = serde_json::from_slice(&input)?;
                match registry.next_registration(author, &snapshots, now()?, 4096)? {
                    Some(instruction) => instruction,
                    None => {
                        return Ok(serde_json::json!({
                            "complete":true,"verification":"matching_registry_records_by_author"
                        }));
                    }
                }
            } else if a[1] == "register" {
                let snapshots: Vec<Snapshot> = serde_json::from_slice(&input)?;
                if snapshots.is_empty() || snapshots.len() > 8 {
                    return Err("Select 1–8 stored snapshots".into());
                }
                let count = registry.catalog()?.count;
                Instruction::RegisterBatch {
                    number: count / 64,
                    expected_count: count,
                    timestamp: now()?,
                    snapshots_json: serde_json::to_string(&snapshots)?,
                }
            } else {
                serde_json::from_slice(&input)?
            };
            let fee = FeeDeclaration::new(author, a[7].parse()?, a[9].parse()?, a[8].parse()?);
            approve_instruction(&registry, &mut session, instruction, fee)
        }
        #[cfg(feature = "hosting")]
        Some("host-local" | "host-fetch" | "host-bulk") => hosting::run(a),
        _ => Err(HELP.into()),
    }
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 2 && matches!(args[1].as_str(), "--help" | "help") {
        print!("{HELP}");
        return;
    }
    match run(&args) {
        Ok(mut value) => {
            // Signed bytes stay in the durable outbox; show concise public status.
            if let Some(rows) = value.as_array_mut() {
                for row in rows {
                    if let Some(object) = row.as_object_mut() {
                        object.remove("transaction");
                    }
                }
            } else if let Some(object) = value.as_object_mut() {
                object.remove("transaction");
            }
            println!("{value}");
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
