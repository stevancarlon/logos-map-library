// SPDX-License-Identifier: MIT OR Apache-2.0
use logos_map_registry::{map_registry::*, *};
use spel_framework::prelude::*;
const PROGRAM: ProgramId = [6; 8];
fn account(id: AccountId, signed: bool) -> AccountWithMetadata {
    AccountWithMetadata {
        account_id: id,
        account: Account::default(),
        is_authorized: signed,
    }
}
fn stored<T: BorshSerialize>(id: AccountId, state: T) -> AccountWithMetadata {
    AccountWithMetadata {
        account_id: id,
        account: Account {
            program_owner: PROGRAM,
            data: borsh::to_vec(&state).unwrap().try_into().unwrap(),
            ..Account::default()
        },
        is_authorized: false,
    }
}
fn inputs() -> Vec<AccountWithMetadata> {
    vec![
        stored(
            compute_pda(&PROGRAM, &[&seed_from_str("maps")]),
            Catalog {
                schema: SCHEMA,
                count: 0,
                last_timestamp: 0,
            },
        ),
        stored(
            compute_pda(&PROGRAM, &[&seed_from_str("map-page"), &0u64.to_seed()]),
            Page {
                schema: SCHEMA,
                number: 0,
                records: vec![],
            },
        ),
        account(AccountId::new([7; 32]), true),
    ]
}
fn snapshot(region: &str) -> Snapshot {
    let (_, parent, level) = regions::REGIONS
        .iter()
        .find(|(r, _, _)| *r == region)
        .unwrap();
    Snapshot {
        region: region.into(),
        parent: parent.map(str::to_owned),
        level: (*level).into(),
        cid: "bafyFixtureMap".into(),
        source_url: format!("https://download.geofabrik.de/{region}-latest.osm.pbf"),
        checksum: [1; 16],
        sha256: [2; 32],
        bytes: 42,
        version: 20261009,
        hosted: true,
    }
}
fn run(accounts: Vec<AccountWithMetadata>, snapshots: Vec<Snapshot>, count: u64) -> SpelResult {
    let [catalog, page, author]: [_; 3] = accounts.try_into().unwrap();
    register_batch(
        catalog,
        page,
        author,
        0,
        count,
        100,
        serde_json::to_string(&snapshots).unwrap(),
    )
}
#[test]
fn batch_is_atomic_and_preserves_signer_and_order() {
    let accounts = inputs();
    __validate_register_batch(&accounts, &PROGRAM, &vec![], &0).unwrap();
    let output = run(
        accounts,
        vec![snapshot("europe/germany"), snapshot("europe/france")],
        0,
    )
    .unwrap();
    let page: Page = borsh::from_slice(output.post_states[1].account().data.as_ref()).unwrap();
    assert_eq!(page.records.len(), 2);
    assert_eq!(page.records[1].ordinal, 1);
    assert_eq!(page.records[0].registrant, [7; 32]);
    assert_eq!(output.timestamp_validity_window.end(), Some(300101));
}
#[test]
fn invalid_member_duplicate_region_or_stale_count_rejects_whole_batch() {
    let good = snapshot("europe/germany");
    let mut bad = good.clone();
    bad.checksum = [0; 16];
    assert!(run(inputs(), vec![good.clone(), bad], 0).is_err());
    assert!(run(inputs(), vec![good.clone(), good.clone()], 0).is_err());
    assert!(run(inputs(), vec![good], 1).is_err());
    assert!(run(inputs(), vec![], 0).is_err());
}
#[test]
fn generated_constraints_reject_unsigned_wrong_owner_and_wrong_pda() {
    for index in 0..3 {
        let mut accounts = inputs();
        match index {
            0 => accounts[2].is_authorized = false,
            1 => accounts[0].account.program_owner = [8; 8],
            _ => accounts[1].account_id = AccountId::new([5; 32]),
        };
        assert!(__validate_register_batch(&accounts, &PROGRAM, &vec![], &0).is_err());
    }
}
#[test]
fn closed_set_hierarchy_source_and_real_calendar_are_enforced() {
    assert_eq!(regions::REGIONS.len(), 72);
    let mut s = snapshot("europe/germany");
    s.version = 20260229;
    assert!(s.validate().is_err());
    s.version = 20240229;
    assert!(s.validate().is_ok());
    s.parent = Some("us".into());
    assert!(s.validate().is_err());
    s.parent = None;
    s.source_url = "https://evil.invalid/map".into();
    assert!(s.validate().is_err());
    let mut s = snapshot("north-america/us/california");
    s.region = "north-america/us".into();
    assert!(s.validate().is_err());
}
#[test]
fn maximum_page_fits_lez_account_limit() {
    let mut s = snapshot("asia/china/guangdong");
    s.cid = "a".repeat(128);
    let page = Page {
        schema: SCHEMA,
        number: 0,
        records: (0..PAGE_SIZE)
            .map(|n| Record {
                snapshot: s.clone(),
                registrant: [1; 32],
                timestamp: 100,
                ordinal: n as u64,
            })
            .collect(),
    };
    let bytes = borsh::to_vec(&page).unwrap();
    assert!(bytes.len() < 100 * 1024);
}
