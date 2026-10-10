// SPDX-License-Identifier: MIT OR Apache-2.0
//! Disposable synthetic registry fixture, not authentic map hosting or adoption.
use lee_core_v03::account::AccountId;
use lee_v03::{PrivateKey, PublicKey, fees::FeeDeclaration};
use logos_maps_v03_publisher::{Publisher, Status, prepare};
use logos_maps_v03_sdk::{Filter, Registry, Snapshot, rpc::Node};
use std::{
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 || !args[1].starts_with("http://127.0.0.1:") {
        return Err("Usage: maps-bulk-chain LOOPBACK_RPC REGISTRY NEW_OUTBOX".into());
    }
    let registry = Registry {
        reader: Node::new(&args[1])?,
        program: args[2].parse()?,
    };
    let key = PrivateKey::try_new([1; 32])?;
    let author = AccountId::from(&PublicKey::new_from_private_key(&key));
    // Exercise enough distinct closed-set entries to cross a 64-record page.
    let selected: Vec<Snapshot> =
        logos_maps_v03_sdk::native::request(r#"{"method":"catalog"}"#)?["canonical_regions"]
            .as_array()
            .ok_or("Catalog missing")?
            .iter()
            .map(|r| {
                let region = r["path"].as_str().unwrap().to_owned();
                Snapshot {
                    source_url: format!("https://download.geofabrik.de/{region}-latest.osm.pbf"),
                    region,
                    parent: r["parent"].as_str().map(str::to_owned),
                    level: r["level"].as_str().unwrap().into(),
                    cid: "bafySyntheticBulkPlannerFixture".into(),
                    checksum: [1; 16],
                    sha256: [2; 32],
                    bytes: 3,
                    version: 20261009,
                    hosted: true,
                }
            })
            .collect();
    assert_eq!(selected.len(), 72);
    let initial = registry.catalog()?.count;
    let path = Path::new(&args[3]);
    let password = b"disposable bulk planner fixture";
    drop(Publisher::create(path, password)?);
    let mut steps = vec![];
    while let Some(instruction) = registry.next_registration(author, &selected, now(), 4096)? {
        if steps.len() >= 16 {
            return Err("Planner did not converge; never retry a write blindly".into());
        }
        let expected = serde_json::to_value(&instruction)?;
        let proposal = prepare(
            &registry,
            author,
            instruction,
            FeeDeclaration::new(author, 10_000_000, 0, 500_000_000),
            now(),
        )?;
        let row = Publisher::open(path)?.approve(password, &registry, proposal, &key, now())?;
        // Reopen the encrypted store for every step; no in-memory progress shortcut.
        let mut publisher = Publisher::open(path)?;
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if publisher
                .reconcile(password, &registry.reader, &row.hash)?
                .status
                == Status::Observed
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err("Observation timeout; do not resubmit".into());
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        if let Some(batch) = expected.get("RegisterBatch") {
            let snapshots: Vec<Snapshot> =
                serde_json::from_str(batch["snapshots_json"].as_str().unwrap())?;
            let count = batch["expected_count"].as_u64().unwrap();
            let page = registry.query(batch["number"].as_u64().unwrap(), &Filter::default())?;
            assert_eq!(page.catalog_count, count + snapshots.len() as u64);
            for (index, snapshot) in snapshots.iter().enumerate() {
                assert!(page.records.iter().any(|r| &r.snapshot == snapshot
                    && r.ordinal == count + index as u64
                    && r.timestamp == batch["timestamp"].as_u64().unwrap()));
            }
        } else if let Some(page) = expected.get("CreatePage") {
            assert!(registry.page_exists(page["number"].as_u64().unwrap())?);
        }
        steps.push(serde_json::json!({"instruction":expected,"hash":row.hash}));
    }
    assert_eq!(registry.catalog()?.count, initial + 72);
    assert!(
        steps
            .iter()
            .any(|s| s["instruction"].get("CreatePage").is_some())
    );
    assert!(
        registry
            .next_registration(author, &selected, now(), 4096)?
            .is_none()
    );
    println!(
        "{}",
        serde_json::json!({"result":"passed","scope":"72 synthetic closed-set snapshots on disposable v0.3 registry; no authentic coverage, UI or public hosting",
        "cross_page_registration":true,"restart_each_step":true,"on_chain_completion":true,"steps":steps,"initial_count":initial,"final_count":initial+72})
    );
    Ok(())
}
