// SPDX-License-Identifier: MIT OR Apache-2.0
use lee_core_v03::account::{AccountId, ProgramShardSelector, ShardData};
use lee_v03::fees::FeeDeclaration;
use logos_maps_v03_sdk::*;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
};
struct Memory {
    states: RefCell<BTreeMap<AccountId, ShardData>>,
    reads: Cell<usize>,
    change: bool,
}
fn id(n: u8) -> AccountId {
    AccountId::new([n; 32])
}
impl Reader for Memory {
    fn shard(&self, selector: ProgramShardSelector) -> Result<ShardData> {
        assert_eq!(selector.program_account_id, id(3));
        let reads = self.reads.get();
        self.reads.set(reads + 1);
        let mut state = self
            .states
            .borrow()
            .get(&selector.account_id)
            .cloned()
            .unwrap_or_default();
        if self.change && reads >= 2 && selector.account_id == catalog_address(id(3)) {
            let mut catalog: Catalog = borsh::from_slice(&state).unwrap();
            catalog.count += 1;
            state = borsh::to_vec(&catalog).unwrap().try_into().unwrap();
        }
        Ok(state)
    }
    fn nonce(&self, account: AccountId) -> Result<u128> {
        assert_eq!(account, id(7));
        Ok(9)
    }
}

#[test]
fn scans_reject_partial_budgets_and_changed_catalogs() {
    let registry = fixture();
    assert_eq!(registry.scan(&Filter::default(), 1).unwrap().len(), 2);
    assert!(registry.scan(&Filter::default(), 0).is_err());
    assert!(registry.scan(&Filter::default(), 4097).is_err());
    let catalog = Catalog {
        schema: SCHEMA,
        count: 65,
        last_timestamp: 101,
    };
    registry.reader.states.borrow_mut().insert(
        catalog_address(id(3)),
        borsh::to_vec(&catalog).unwrap().try_into().unwrap(),
    );
    assert!(registry.scan(&Filter::default(), 1).is_err());
    let mut registry = fixture();
    registry.reader.change = true;
    assert!(registry.scan(&Filter::default(), 1).is_err());
}

#[cfg(feature = "distribution")]
#[test]
fn bulk_selection_and_batches_preserve_opt_outs_and_page_limits() {
    use logos_maps_v03_sdk::distribution::{batches, selection};
    let selected = selection(&[
        "africa/ethiopia".into(),
        "north-america/us/california".into(),
    ])
    .unwrap();
    assert_eq!(selected.len(), 2);
    assert!(selection(&["north-america/us".into()]).is_err());
    assert!(selection(&["africa/ethiopia".into(), "africa/ethiopia".into()]).is_err());
    assert!(selection(&[]).is_err());
    let plan = batches(63, 10).unwrap();
    assert_eq!(
        plan.iter()
            .map(|b| (b.expected_count, b.number, b.start, b.end))
            .collect::<Vec<_>>(),
        vec![(63, 0, 0, 1), (64, 1, 1, 9), (72, 1, 9, 10)]
    );
    assert!(batches(u64::MAX, 1).is_err());
    assert!(batches(0, 73).is_err());
}

#[cfg(feature = "distribution")]
#[test]
fn update_comparison_matches_exact_paths_and_highest_registered_version() {
    use logos_maps_v03_sdk::distribution::{SourceVersion, compare_updates};
    let registry = fixture();
    let mut records = registry.query(0, &Filter::default()).unwrap().records;
    let mut older = records[0].clone();
    older.snapshot.version = 20261001;
    older.timestamp = 200;
    records.push(older);
    let sources = [
        ("europe/germany", 20261009),
        ("africa/ethiopia", 20261010),
        ("europe/france", 20261010),
    ]
    .into_iter()
    .map(|(region, version)| SourceVersion {
        region: region.into(),
        version,
        dated_url: String::new(),
    })
    .collect();
    let result = compare_updates(sources, &records);
    assert_eq!(result[0].registry_version, Some(20261009));
    assert!(!result[0].update_available);
    assert!(result[1].update_available);
    assert_eq!(result[2].registry_version, None);
    assert!(!result[2].update_available);
}
fn snapshot(region: &str) -> Snapshot {
    let (_, parent, level) = logos_map_registry::regions::REGIONS
        .iter()
        .find(|r| r.0 == region)
        .unwrap();
    Snapshot {
        region: region.into(),
        parent: parent.map(str::to_owned),
        level: (*level).into(),
        cid: "bafySyntheticFixture".into(),
        source_url: format!("https://download.geofabrik.de/{region}-latest.osm.pbf"),
        checksum: [1; 16],
        sha256: [2; 32],
        bytes: 3,
        version: 20261009,
        hosted: true,
    }
}
fn fixture() -> Registry<Memory> {
    let catalog = Catalog {
        schema: SCHEMA,
        count: 2,
        last_timestamp: 101,
    };
    let page = Page {
        schema: SCHEMA,
        number: 0,
        records: ["africa/ethiopia", "europe/germany"]
            .into_iter()
            .enumerate()
            .map(|(i, r)| Record {
                snapshot: snapshot(r),
                registrant: [7; 32],
                timestamp: 100 + i as u64,
                ordinal: i as u64,
            })
            .collect(),
    };
    Registry {
        program: id(3),
        reader: Memory {
            states: RefCell::new(
                [
                    (
                        catalog_address(id(3)),
                        borsh::to_vec(&catalog).unwrap().try_into().unwrap(),
                    ),
                    (
                        page_address(id(3), 0),
                        borsh::to_vec(&page).unwrap().try_into().unwrap(),
                    ),
                ]
                .into(),
            ),
            reads: Cell::new(0),
            change: false,
        },
    }
}
#[test]
fn queries_filter_sort_and_bound_pages() {
    let registry = fixture();
    let all = registry.query(0, &Filter::default()).unwrap();
    assert_eq!(all.records[0].snapshot.region, "europe/germany");
    assert!(all.next_page.is_none());
    assert_eq!(all.verification, "unverified_hosting_assertions");
    assert_eq!(
        registry
            .query(
                0,
                &Filter {
                    region: Some("africa/ethiopia"),
                    ..Default::default()
                }
            )
            .unwrap()
            .records
            .len(),
        1
    );
    assert_eq!(
        registry
            .query(
                0,
                &Filter {
                    cid: Some("bafySyntheticFixture"),
                    ..Default::default()
                }
            )
            .unwrap()
            .records
            .len(),
        2
    );
    assert!(
        registry
            .query(
                0,
                &Filter {
                    parent: Some("us"),
                    ..Default::default()
                }
            )
            .unwrap()
            .records
            .is_empty()
    );
    assert!(
        registry
            .query(1, &Filter::default())
            .unwrap()
            .records
            .is_empty()
    );
    assert!(registry.query(u64::MAX, &Filter::default()).is_err());
}
#[test]
fn concurrent_catalog_change_is_rejected() {
    let mut registry = fixture();
    registry.reader.change = true;
    assert!(registry.query(0, &Filter::default()).is_err());
}
#[test]
fn malformed_pages_and_forged_metadata_are_rejected() {
    for alteration in 0..5 {
        let registry = fixture();
        let address = page_address(id(3), 0);
        let mut page: Page = borsh::from_slice(&registry.reader.states.borrow()[&address]).unwrap();
        match alteration {
            0 => page.number = 8,
            1 => page.records[0].ordinal = 9,
            2 => page.records[0].snapshot.parent = Some("us".into()),
            3 => page.records[0].timestamp = 102,
            _ => {
                page.records.pop();
            }
        }
        registry
            .reader
            .states
            .borrow_mut()
            .insert(address, borsh::to_vec(&page).unwrap().try_into().unwrap());
        assert!(registry.query(0, &Filter::default()).is_err());
    }
}
#[test]
fn prepared_message_binds_exact_states_nonce_and_fee() {
    let registry = fixture();
    let fee = FeeDeclaration::new(id(7), 1_000_000, 2, 100_000_000);
    let instruction = Instruction::RegisterBatch {
        number: 0,
        expected_count: 2,
        timestamp: 102,
        snapshots_json: serde_json::to_string(&vec![snapshot("europe/france")]).unwrap(),
    };
    let message = registry.prepare(id(7), &instruction, fee).unwrap();
    assert_eq!(message.nonces, vec![9u128.into()]);
    assert_eq!(message.fee, Some(fee));
    let request: logos_maps_v03_core::Request =
        borsh::from_slice(&message.instruction_data).unwrap();
    assert_eq!(
        request.states[0],
        registry.reader.states.borrow()[&catalog_address(id(3))]
    );
    assert_eq!(
        request.states[1],
        registry.reader.states.borrow()[&page_address(id(3), 0)]
    );
    assert!(
        registry
            .prepare(id(7), &instruction, FeeDeclaration::new(id(8), 1, 0, 1))
            .is_err()
    );
    assert!(
        registry
            .prepare(id(7), &Instruction::Initialize {}, fee)
            .is_err()
    );
}

#[test]
fn registration_planner_requires_exact_author_records_and_valid_state() {
    let registry = fixture();
    let selected = vec![snapshot("africa/ethiopia"), snapshot("europe/germany")];
    assert!(
        registry
            .next_registration(id(7), &selected, 200, 1)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        registry
            .next_registration(id(8), &selected, 200, 1)
            .unwrap(),
        Some(Instruction::RegisterBatch { .. })
    ));
    assert!(
        registry
            .next_registration(id(7), &selected, 200, 0)
            .is_err()
    );
    assert!(
        registry
            .next_registration(id(7), &[selected[0].clone(), selected[0].clone()], 200, 1)
            .is_err()
    );
    registry.reader.states.borrow_mut().clear();
    assert!(matches!(
        registry
            .next_registration(id(7), &selected, 200, 1)
            .unwrap(),
        Some(Instruction::Initialize)
    ));
    let mut invalid = selected.clone();
    invalid[0].region = "unsupported".into();
    assert!(registry.next_registration(id(7), &invalid, 200, 1).is_err());
    registry
        .reader
        .states
        .borrow_mut()
        .insert(catalog_address(id(3)), vec![1, 2, 3].try_into().unwrap());
    assert!(
        registry
            .next_registration(id(7), &selected, 200, 1)
            .is_err()
    );
}

#[test]
fn registration_planner_splits_at_page_edge_and_requests_missing_page() {
    let registry = fixture();
    let selected: Vec<_> = logos_map_registry::regions::REGIONS
        .iter()
        .take(10)
        .map(|r| snapshot(r.0))
        .collect();
    for count in [63u64, 64] {
        let records = (0..count)
            .map(|i| {
                let mut value = snapshot("africa/ethiopia");
                value.cid = format!("bafyHistoricalFixture{i}");
                Record {
                    snapshot: value,
                    registrant: [7; 32],
                    timestamp: i + 1,
                    ordinal: i,
                }
            })
            .collect();
        let mut states = registry.reader.states.borrow_mut();
        states.insert(
            catalog_address(id(3)),
            borsh::to_vec(&Catalog {
                schema: SCHEMA,
                count,
                last_timestamp: count,
            })
            .unwrap()
            .try_into()
            .unwrap(),
        );
        states.insert(
            page_address(id(3), 0),
            borsh::to_vec(&Page {
                schema: SCHEMA,
                number: 0,
                records,
            })
            .unwrap()
            .try_into()
            .unwrap(),
        );
        drop(states);
        let step = registry
            .next_registration(id(7), &selected, 200, 2)
            .unwrap()
            .unwrap();
        if count == 63 {
            match step {
                Instruction::RegisterBatch {
                    number,
                    expected_count,
                    snapshots_json,
                    ..
                } => {
                    assert_eq!((number, expected_count), (0, 63));
                    assert_eq!(
                        serde_json::from_str::<Vec<Snapshot>>(&snapshots_json).unwrap(),
                        selected[..1]
                    );
                }
                _ => panic!("must fill the remaining page slot"),
            }
        } else {
            assert!(matches!(step, Instruction::CreatePage { number: 1 }));
        }
    }
    registry.reader.states.borrow_mut().insert(
        page_address(id(3), 1),
        borsh::to_vec(&Page {
            schema: SCHEMA,
            number: 1,
            records: vec![],
        })
        .unwrap()
        .try_into()
        .unwrap(),
    );
    match registry
        .next_registration(id(7), &selected, 200, 2)
        .unwrap()
        .unwrap()
    {
        Instruction::RegisterBatch {
            number,
            expected_count,
            snapshots_json,
            ..
        } => {
            assert_eq!((number, expected_count), (1, 64));
            assert_eq!(
                serde_json::from_str::<Vec<Snapshot>>(&snapshots_json).unwrap(),
                selected[..8]
            );
        }
        _ => panic!("must cap the next batch at eight"),
    }
}

#[test]
fn scans_order_across_pages_and_break_timestamp_ties_by_ordinal() {
    let registry = fixture();
    let count = PAGE_SIZE as u64 + 2;
    let records: Vec<_> = (0..count)
        .map(|ordinal| Record {
            snapshot: snapshot("africa/ethiopia"),
            registrant: [7; 32],
            timestamp: 100 + ordinal / 2,
            ordinal,
        })
        .collect();
    let mut states = registry.reader.states.borrow_mut();
    states.insert(
        catalog_address(id(3)),
        borsh::to_vec(&Catalog {
            schema: SCHEMA,
            count,
            last_timestamp: records.last().unwrap().timestamp,
        })
        .unwrap()
        .try_into()
        .unwrap(),
    );
    for (number, chunk) in records.chunks(PAGE_SIZE).enumerate() {
        states.insert(
            page_address(id(3), number as u64),
            borsh::to_vec(&Page {
                schema: SCHEMA,
                number: number as u64,
                records: chunk.to_vec(),
            })
            .unwrap()
            .try_into()
            .unwrap(),
        );
    }
    drop(states);
    let first = registry.query(0, &Filter::default()).unwrap();
    assert_eq!(first.next_page, Some(1));
    assert_eq!(first.records[0].ordinal, PAGE_SIZE as u64 - 1);
    let all = registry.scan(&Filter::default(), 2).unwrap();
    assert_eq!(
        all.iter().map(|record| record.ordinal).collect::<Vec<_>>(),
        (0..count).rev().collect::<Vec<_>>()
    );
    assert!(all.windows(2).all(|pair| pair[0].timestamp >= pair[1].timestamp));
}
