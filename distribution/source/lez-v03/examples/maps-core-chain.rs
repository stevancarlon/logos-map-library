// SPDX-License-Identifier: MIT OR Apache-2.0
//! Disposable signed deployment and state-transition fixture. Loopback only.
use base64::{Engine, engine::general_purpose::STANDARD};
use lee_core_v03::{
    account::{AccountId, ProgramShardSelector, ShardData},
    program::{PROGRAM_LOADER_ACCOUNT_ID, PdaSeed},
};
use lee_v03::{
    PrivateKey, PublicKey, PublicTransaction,
    fees::FeeDeclaration,
    public_transaction::{Message, WitnessSet},
};
use logos_lez_v03::{Node, ShardSelector, transfer::NativeReader};
use logos_map_registry::{Catalog, Instruction, Page, Snapshot};
use logos_maps_v03_core::{ENVELOPE_VERSION, Request};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn account(key: &PrivateKey) -> AccountId {
    AccountId::from(&PublicKey::new_from_private_key(key))
}
fn local(id: AccountId) -> logos_lez_v03::AccountId {
    logos_lez_v03::AccountId::from_bytes(*id.value())
}
struct Fixture {
    node: Node,
    endpoint: String,
    agent: ureq::Agent,
    payer: PrivateKey,
    hashes: Vec<String>,
}
impl Fixture {
    fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        let envelope: Value = self
            .agent
            .post(&self.endpoint)
            .send_json(json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))?
            .body_mut()
            .with_config()
            .limit(2 * 1024 * 1024)
            .read_json()?;
        if envelope.get("error").is_some()
            || envelope.get("id") != Some(&json!(1))
            || envelope.get("jsonrpc") != Some(&json!("2.0"))
        {
            return Err(format!("Unexpected RPC response: {envelope}").into());
        }
        envelope
            .get("result")
            .cloned()
            .ok_or_else(|| "Missing RPC result".into())
    }
    fn shard(&self, id: AccountId, program: AccountId) -> Result<ShardData> {
        let view = self.node.account_view(&ShardSelector {
            account_id: local(id),
            program_account_id: local(program),
        })?;
        Ok(view
            .data
            .shards
            .get(&local(program))
            .cloned()
            .unwrap_or_default()
            .try_into()?)
    }
    fn send<T: borsh::BorshSerialize>(
        &mut self,
        program: AccountId,
        ids: &[AccountId],
        instruction: T,
        extra: Option<&PrivateKey>,
    ) -> Result<String> {
        let payer = account(&self.payer);
        let mut keys = vec![&self.payer];
        if let Some(key) = extra {
            keys.push(key);
        }
        let nonces = keys
            .iter()
            .map(|key| {
                self.node
                    .native_view(local(account(key)))
                    .map(|view| view.nonce.into())
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let before = self.node.native_view(local(payer))?;
        let message = Message::try_new_with_fees(
            program,
            ids.iter()
                .map(|id| ProgramShardSelector::new(*id, program))
                .collect(),
            nonces,
            instruction,
            FeeDeclaration::new(payer, 10_000_000, 0, 100_000_000),
        )?;
        let witness = WitnessSet::for_message(&message, &keys);
        let tx = PublicTransaction::new(message, witness);
        let hash = hex::encode(tx.hash());
        // Preserve the exact expected transaction; inclusion must return identical bytes.
        let mut wire = vec![0];
        wire.extend(borsh::to_vec(&tx)?);
        let returned = self.rpc("sendTransaction", json!([STANDARD.encode(&wire)]))?;
        if returned != json!(hash) {
            return Err("Submission hash mismatch".into());
        }
        self.hashes.push(hash.clone());
        let start = Instant::now();
        loop {
            let seen = self.rpc("getTransaction", json!([hash]))?;
            if !seen.is_null() {
                let pair: (String, u64) = serde_json::from_value(seen)?;
                if STANDARD.decode(pair.0)? != wire {
                    return Err("Included bytes differ".into());
                }
                break;
            }
            if start.elapsed() > Duration::from_secs(180) {
                return Err(format!("Uncertain inclusion for {hash}; never resubmitted").into());
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        let after = self.node.native_view(local(payer))?;
        if after.nonce != before.nonce + 1
            || before.native_balance()? <= after.native_balance()?
            || before.native_balance()? - after.native_balance()? > 100_000_000
        {
            return Err("Unexpected payer nonce or fee debit".into());
        }
        Ok(hash)
    }
    fn map_write(
        &mut self,
        registry: AccountId,
        ids: &[AccountId],
        instruction: Instruction,
    ) -> Result<String> {
        let request = Request {
            version: ENVELOPE_VERSION,
            instruction_json: serde_json::to_string(&instruction)?,
            states: ids
                .iter()
                .map(|id| self.shard(*id, registry))
                .collect::<Result<_>>()?,
        };
        let mut inputs = ids.to_vec();
        inputs.push(account(&self.payer));
        self.send(registry, &inputs, request, None)
    }
}
fn seed(text: &str) -> [u8; 32] {
    let mut seed = [0; 32];
    seed[..text.len()].copy_from_slice(text.as_bytes());
    seed
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let payer = PrivateKey::try_new([1; 32])?;
    if args.get(1).map(String::as_str) == Some("fixture-account") {
        println!("{}", account(&payer));
        return Ok(());
    }
    if args.len() != 3 {
        return Err("Usage: maps-chain LOOPBACK_RPC UNUSED_FIXTURE_PATH".into());
    }
    let endpoint = &args[1];
    let uri: ureq::http::Uri = endpoint.parse()?;
    if uri.scheme_str() != Some("http")
        || uri.host() != Some("127.0.0.1")
        || uri.port_u16().is_none()
    {
        return Err("Disposable loopback sequencer required".into());
    }
    let mut f = Fixture {
        node: Node::new(endpoint)?,
        endpoint: endpoint.clone(),
        payer,
        hashes: vec![],
        agent: ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(120)))
            .max_redirects(0)
            .build()
            .into(),
    };
    let guest = std::fs::read("artifacts/maps-v03/program.elf")?;
    let image: [u32; 8] =
        risc0_binfmt::ProgramBinary::new(&guest, risc0_zkos_v1compat::V1COMPAT_ELF)
            .compute_image_id()?
            .into();
    let header_key = PrivateKey::try_new([3; 32])?;
    let registry = account(&header_key);
    let chunks: Vec<_> = guest
        .chunks(program_loader_core_v03::MAX_SEGMENT_DATA_LEN)
        .collect();
    let segments: Vec<_> = (0..chunks.len())
        .map(|i| AccountId::new([20 + u8::try_from(i).unwrap(); 32]))
        .collect();
    for i in (0..chunks.len()).rev() {
        let next = segments.get(i + 1).copied();
        let mut ids = vec![segments[i]];
        ids.extend(next);
        f.send(
            PROGRAM_LOADER_ACCOUNT_ID,
            &ids,
            program_loader_core_v03::Instruction::WriteSegment {
                bytecode: chunks[i].to_vec(),
                next_segment: next,
            },
            None,
        )?;
    }
    let mut ids = vec![registry];
    ids.extend(&segments);
    f.send(
        PROGRAM_LOADER_ACCOUNT_ID,
        &ids,
        program_loader_core_v03::Instruction::CreateHeader {
            first_segment: segments[0],
            immutable: true,
        },
        Some(&header_key),
    )?;
    let deployment = logos_lez_v03::deployment::inspect(&f.node, local(registry), image)?;
    let catalog = AccountId::for_public_pda(&registry, &PdaSeed::new(seed("maps")));
    let mut hash = Sha256::new();
    hash.update(seed("map-page"));
    hash.update([0; 32]);
    let page = AccountId::for_public_pda(&registry, &PdaSeed::new(hash.finalize().into()));
    f.map_write(registry, &[catalog], Instruction::Initialize)?;
    f.map_write(registry, &[page], Instruction::CreatePage { number: 0 })?;
    for (count, size) in [(0u64, 1usize), (1, 8)] {
        let snapshots: Vec<_> = logos_map_registry::regions::REGIONS
            .iter()
            .skip(count as usize)
            .take(size)
            .map(|(region, parent, level)| Snapshot {
                region: (*region).into(),
                parent: parent.map(str::to_owned),
                level: (*level).into(),
                cid: "bafySyntheticFixture".into(),
                source_url: format!("https://download.geofabrik.de/{region}-latest.osm.pbf"),
                checksum: [1; 16],
                sha256: [2; 32],
                bytes: 3,
                version: 20261009,
                hosted: true,
            })
            .collect();
        f.map_write(
            registry,
            &[catalog, page],
            Instruction::RegisterBatch {
                number: 0,
                expected_count: count,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)?
                    .as_millis()
                    .try_into()?,
                snapshots_json: serde_json::to_string(&snapshots)?,
            },
        )?;
    }
    let observed: Catalog = borsh::from_slice(&f.shard(catalog, registry)?)?;
    let records: Page = borsh::from_slice(&f.shard(page, registry)?)?;
    if observed.count != 9 || records.records.len() != 9 {
        return Err("Wrong resulting record count".into());
    }
    for (i, r) in records.records.iter().enumerate() {
        if r.ordinal != i as u64 || r.registrant != *account(&f.payer).value() {
            return Err("Record identity/order mismatch".into());
        }
        r.snapshot.validate()?;
    }
    println!(
        "{}",
        json!({"result":"passed","registry":registry.to_string(),"deployment":deployment,"transactions":f.hashes,
        "records":9,"single_and_batch_registration":true,"payer_nonce_and_fee_verified":true,
        "scope":"Signed local v0.3 deployment/registration with synthetic snapshots. No public hosting, testnet deployment or independent adoption."})
    );
    Ok(())
}
