// SPDX-License-Identifier: MIT OR Apache-2.0
//! Disposable local fixture. Fixed keys/automatic signing MUST NOT be used outside this test.
use anyhow::{Result, ensure};
use lee_core_v03::{
    account::{AccountId, ProgramShardSelector},
    program::{PROGRAM_LOADER_ACCOUNT_ID, ProgramHeader},
};
use lee_v03::{
    PrivateKey, PublicKey, PublicTransaction,
    fees::FeeDeclaration,
    public_transaction::{Message, WitnessSet},
};
use logos_maps_v03_sdk::{Filter, Instruction, Reader, Registry, Snapshot, rpc::Node};
use std::{
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
fn account(key: &PrivateKey) -> AccountId {
    AccountId::from(&PublicKey::new_from_private_key(key))
}
fn fee(payer: AccountId) -> FeeDeclaration {
    FeeDeclaration::new(payer, 10_000_000, 0, 500_000_000)
}
fn submit(node: &Node, message: Message, keys: &[&PrivateKey], saved: &Path) -> Result<String> {
    let witnesses = WitnessSet::for_message(&message, keys);
    ensure!(witnesses.is_valid_for(&message));
    let tx = PublicTransaction::new(message, witnesses);
    let hash = hex::encode(tx.hash());
    // Preserve exact bytes before network I/O. Each hash is a new fixture file.
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(saved.join(&hash))?;
    file.write_all(&borsh::to_vec(&tx)?)?;
    file.sync_all()?;
    node.broadcast(&tx)?;
    let started = Instant::now();
    loop {
        if node.observed(&tx)? {
            break;
        }
        ensure!(
            started.elapsed() < Duration::from_secs(120),
            "Transaction {hash} unobserved; do not retry"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    Ok(hash)
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let payer = PrivateKey::try_new([1; 32])?;
    let author = account(&payer);
    if args.get(1).map(String::as_str) == Some("fixture-account") {
        println!("{author}");
        return Ok(());
    }
    ensure!(
        args.len() == 3,
        "Usage: maps-chain LOOPBACK_RPC NEW_SAVED_DIRECTORY"
    );
    let uri: ureq::http::Uri = args[1].parse()?;
    ensure!(
        uri.scheme_str() == Some("http")
            && uri.host() == Some("127.0.0.1")
            && uri.port_u16().is_some(),
        "Disposable loopback only"
    );
    let saved = Path::new(&args[2]);
    std::fs::create_dir(saved)?;
    let node = Node::new(&args[1])?;
    let elf = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../artifacts/maps-v03/program.elf"
    ))?;
    let expected_image: [u32; 8] =
        risc0_binfmt::ProgramBinary::new(&elf, risc0_zkos_v1compat::V1COMPAT_ELF)
            .compute_image_id()?
            .into();
    let header_key = PrivateKey::try_new([3; 32])?;
    let program = account(&header_key);
    let chunks: Vec<_> = elf
        .chunks(program_loader_v03::MAX_SEGMENT_DATA_LEN)
        .collect();
    ensure!(chunks.len() <= program_loader_v03::MAX_PROGRAM_SEGMENTS);
    let segments: Vec<_> = (0..chunks.len())
        .map(|i| account(&PrivateKey::try_new([10 + i as u8; 32]).unwrap()))
        .collect();
    let mut transactions = vec![];
    for i in (0..chunks.len()).rev() {
        let next = segments.get(i + 1).copied();
        let selectors = std::iter::once(segments[i])
            .chain(next)
            .map(|id| ProgramShardSelector::new(id, PROGRAM_LOADER_ACCOUNT_ID))
            .collect();
        let message = Message::try_new_with_fees(
            PROGRAM_LOADER_ACCOUNT_ID,
            selectors,
            vec![node.nonce(author)?.into()],
            program_loader_v03::Instruction::WriteSegment {
                bytecode: chunks[i].to_vec(),
                next_segment: next,
            },
            fee(author),
        )?;
        transactions.push(submit(&node, message, &[&payer], saved)?);
    }
    let message = Message::try_new_with_fees(
        PROGRAM_LOADER_ACCOUNT_ID,
        std::iter::once(program)
            .chain(segments.iter().copied())
            .map(|id| ProgramShardSelector::new(id, PROGRAM_LOADER_ACCOUNT_ID))
            .collect(),
        vec![node.nonce(program)?.into(), node.nonce(author)?.into()],
        program_loader_v03::Instruction::CreateHeader {
            first_segment: segments[0],
            immutable: true,
        },
        fee(author),
    )?;
    transactions.push(submit(&node, message, &[&header_key, &payer], saved)?);
    let shard = node.shard(ProgramShardSelector::new(
        program,
        PROGRAM_LOADER_ACCOUNT_ID,
    ))?;
    let header = ProgramHeader::from_bytes(&shard)
        .ok_or_else(|| anyhow::anyhow!("Missing loader header"))?;
    ensure!(
        header.image_id == expected_image && header.immutable,
        "Deployed image/header mismatch"
    );
    let registry = Registry {
        reader: node,
        program,
    };
    for instruction in [
        Instruction::Initialize {},
        Instruction::CreatePage { number: 0 },
    ] {
        let message = registry.prepare(author, &instruction, fee(author))?;
        transactions.push(submit(&registry.reader, message, &[&payer], saved)?);
    }
    for (count, size) in [(0u64, 1usize), (1, 8)] {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
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
        let instruction = Instruction::RegisterBatch {
            number: 0,
            expected_count: count,
            timestamp,
            snapshots_json: serde_json::to_string(&snapshots)?,
        };
        let message = registry.prepare(author, &instruction, fee(author))?;
        transactions.push(submit(&registry.reader, message, &[&payer], saved)?);
        ensure!(registry.catalog()?.count == count + size as u64);
        ensure!(
            registry.prepare(author, &instruction, fee(author)).is_err(),
            "Stale expected count accepted"
        );
    }
    let page = registry.query(0, &Filter::default())?;
    ensure!(page.records.len() == 9 && page.next_page.is_none());
    let region = &page.records[0].snapshot.region;
    ensure!(
        registry
            .query(
                0,
                &Filter {
                    region: Some(region),
                    ..Default::default()
                }
            )?
            .records
            .len()
            == 1
    );
    ensure!(
        registry
            .query(
                0,
                &Filter {
                    cid: Some("bafySyntheticFixture"),
                    ..Default::default()
                }
            )?
            .records
            .len()
            == 9
    );
    ensure!(
        registry
            .query(
                0,
                &Filter {
                    parent: Some("missing"),
                    ..Default::default()
                }
            )?
            .records
            .is_empty()
    );
    ensure!(page.records.iter().all(|r| r.registrant == *author.value()));
    let mut hosting = serde_json::Value::Null;
    #[cfg(feature = "distribution")]
    if let Ok(mode) = std::env::var("MAPS_HOST_MODE") {
        use logos_maps_v03_sdk::distribution::{Distribution, StorageNode};
        ensure!(matches!(mode.as_str(), "local" | "fetch"));
        let storage_api = std::env::var("MAPS_HOST_STORAGE_API")?;
        let uri: ureq::http::Uri = storage_api.parse()?;
        ensure!(
            uri.scheme_str() == Some("http") && uri.host() == Some("127.0.0.1"),
            "Isolated Storage only"
        );
        let version: u32 = std::env::var("MAPS_HOST_VERSION")?.parse()?;
        let source = std::env::var("MAPS_HOST_SOURCE")?;
        let distribution = Distribution {
            registry,
            storage: StorageNode::new(&storage_api)?,
        };
        let limit = 200_000_000;
        use logos_maps_v03_sdk::distribution::{HostInput, HostItem, HostOutcome};
        let items = [
            HostItem {
                region: "africa/ethiopia".into(),
                version,
                selected: true,
                input: if mode == "local" {
                    HostInput::Local {
                        path: source.into(),
                    }
                } else {
                    HostInput::Fetch {
                        destination: saved.join("fetched.osm.pbf"),
                    }
                },
            },
            HostItem {
                region: "europe/germany".into(),
                version,
                selected: false,
                input: HostInput::Local {
                    path: saved.join("must-not-open-disabled-file"),
                },
            },
        ];
        let mut progress = 0;
        let mut outcomes = distribution.store_bulk(&items, limit, saved, |_| {
            progress += 1;
            true
        })?;
        ensure!(outcomes.len() == 1 && progress == 1, "Opted-out item ran");
        let snapshot = match outcomes.remove(0) {
            HostOutcome::Stored { snapshot } => snapshot,
            HostOutcome::Failed { error, .. } => anyhow::bail!("{error}"),
        };
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
        let message = distribution.prepare_registration(
            author,
            std::slice::from_ref(&snapshot),
            timestamp,
            fee(author),
        )?;
        let hash = submit(&distribution.registry.reader, message, &[&payer], saved)?;
        transactions.push(hash.clone());
        let found = distribution.registry.query(
            0,
            &Filter {
                region: Some("africa/ethiopia"),
                cid: Some(&snapshot.cid),
                ..Default::default()
            },
        )?;
        ensure!(found.records.len() == 1 && found.records[0].snapshot == snapshot);
        let downloaded = distribution.download_hosted(
            &found.records[0].snapshot,
            limit,
            &saved.join("downloaded.osm.pbf"),
        )?;
        ensure!(
            downloaded.md5 == hex::encode(snapshot.checksum)
                && downloaded.sha256 == hex::encode(snapshot.sha256)
                && downloaded.bytes == snapshot.bytes
        );
        let updates = distribution.check_updates(&["africa/ethiopia".into()], 2)?;
        ensure!(updates.len() == 1 && updates[0].registry_version == Some(snapshot.version));
        ensure!(updates[0].source.version >= snapshot.version);
        ensure!(updates[0].update_available == (updates[0].source.version > snapshot.version));
        hosting = serde_json::json!({"mode":mode,"snapshot":snapshot,"downloaded":downloaded,"registration":hash,
            "bulk_opt_out_respected":true,"updates":updates,
            "scope":"Authentic dated Geofabrik extract, import-time MD5 rechecked, isolated real Storage upload, signed local v0.3 registration, SDK query and hosted download. Not public hosting or testnet."});
    }
    println!(
        "{}",
        serde_json::json!({"result":"passed","program_account":program,"image_id":expected_image,
        "transactions":transactions,"synthetic_records":9,"hosting":hosting,"single_and_batch_registration":true,"sdk_queries":true,
        "stale_count_rejected":true,"scope":"Local v0.3 signed loader deployment and SDK registration/query. Nine synthetic records are separate from optional authentic hosting evidence. No public testnet, independent finality or adoption."})
    );
    Ok(())
}
