// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fixed-key, disposable loopback fixture. Never use this identity outside tests.
use lee_core_v03::account::AccountId;
use lee_v03::{PrivateKey, PublicKey, fees::FeeDeclaration};
use logos_maps_v03_publisher::{Publisher, Status, prepare};
use logos_maps_v03_sdk::{Filter, Instruction, Registry, Snapshot, rpc::Node};
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
    if args.len() != 4 {
        return Err("Usage: maps-publisher-chain LOOPBACK_RPC REGISTRY NEW_OUTBOX".into());
    }
    if !args[1].starts_with("http://127.0.0.1:") {
        return Err("Loopback fixture only".into());
    }
    let registry = Registry {
        reader: Node::new(&args[1])?,
        program: args[2].parse()?,
    };
    let key = PrivateKey::try_new([1; 32])?;
    let author = AccountId::from(&PublicKey::new_from_private_key(&key));
    let password = b"disposable map publisher fixture";
    let path = Path::new(&args[3]);
    let mut publisher = Publisher::create(path, password)?;
    let catalog = registry.catalog()?;
    let timestamp = now();
    let snapshot = Snapshot {
        region: "africa/kenya".into(),
        parent: None,
        level: "country".into(),
        source_url: "https://download.geofabrik.de/africa/kenya-latest.osm.pbf".into(),
        cid: "bafySyntheticPublisherFixture".into(),
        checksum: [1; 16],
        sha256: [2; 32],
        bytes: 3,
        version: 20261009,
        hosted: true,
    };
    let instruction = Instruction::RegisterBatch {
        number: catalog.count / 64,
        expected_count: catalog.count,
        timestamp,
        snapshots_json: serde_json::to_string(&vec![snapshot])?,
    };
    let proposal = prepare(
        &registry,
        author,
        instruction,
        FeeDeclaration::new(author, 10_000_000, 0, 500_000_000),
        now(),
    )?;
    let review = serde_json::to_value(proposal.review())?;
    let row = publisher.approve(password, &registry, proposal, &key, now())?;
    assert!(matches!(
        row.status,
        Status::Acknowledged | Status::SubmissionUnknown
    ));
    drop(publisher);
    let mut recovered = Publisher::open(path)?;
    let started = Instant::now();
    loop {
        if recovered
            .reconcile(password, &registry.reader, &row.hash)?
            .status
            == Status::Observed
        {
            break;
        }
        if started.elapsed() > Duration::from_secs(120) {
            return Err("Saved transaction not observed; do not resend".into());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let records = registry.query(
        catalog.count / 64,
        &Filter {
            region: Some("africa/kenya"),
            ..Default::default()
        },
    )?;
    assert_eq!(records.catalog_count, catalog.count + 1);
    assert!(
        records
            .records
            .iter()
            .any(|r| r.snapshot.cid == "bafySyntheticPublisherFixture" && r.timestamp == timestamp)
    );
    drop(recovered);
    let rows = Publisher::open(path)?.submissions(password)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, Status::Observed);
    println!(
        "{}",
        serde_json::json!({"result":"passed","scope":"synthetic local chain registration; fixed fixture key, no user approval UI or public hosting", "review":review,"hash":row.hash,"restart_recovery":true,"resulting_registry_count":records.catalog_count,"resulting_record_checked":true})
    );
    Ok(())
}
