// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use lee_core_v03::program::{AccountMeta, PdaSeed, validate_apply_output, validate_plan};
use std::collections::BTreeMap;

fn id(n: u8) -> AccountId {
    AccountId::new([n; 32])
}
fn pda(seeds: &[&[u8; 32]]) -> AccountId {
    let old = old::compute_pda(&spel_program_identity(id(3)), seeds);
    AccountId::new(*old.value())
}
fn catalog() -> AccountId {
    pda(&[&old::seed_from_str("maps")])
}
fn page() -> AccountId {
    use old::ToSeed;
    pda(&[&old::seed_from_str("map-page"), &0u64.to_seed()])
}
fn call(
    instruction: Instruction,
    ids: &[AccountId],
    states: &BTreeMap<AccountId, ShardData>,
) -> (PlanInput, Request) {
    let request = Request {
        version: ENVELOPE_VERSION,
        instruction_json: serde_json::to_string(&instruction).unwrap(),
        states: ids
            .iter()
            .map(|id| states.get(id).cloned().unwrap_or_default())
            .collect(),
    };
    let input = PlanInput {
        self_account_id: id(3),
        caller_account_id: None,
        accounts: ids
            .iter()
            .map(|id| AccountMeta::new(*id, false, self::id(3)))
            .chain([AccountMeta::new(id(7), true, id(3))])
            .collect(),
        instruction_data: borsh::to_vec(&request).unwrap(),
    };
    (input, request)
}
fn execute(input: &PlanInput, request: &Request, states: &mut BTreeMap<AccountId, ShardData>) {
    let plan = plan(input, request).unwrap();
    validate_plan(input, plan.output()).unwrap();
    let mut staged = states.clone();
    for effect in &plan.output().effects {
        let call = ApplyInput {
            self_account_id: input.self_account_id,
            selector: effect.selector,
            pre_data: states
                .get(&effect.selector.account_id)
                .cloned()
                .unwrap_or_default(),
            effect_data: effect.data.clone(),
        };
        let output = apply(call.clone()).unwrap();
        validate_apply_output(&call, &output).unwrap();
        staged.insert(effect.selector.account_id, output.post_data.unwrap());
    }
    *states = staged;
}
fn initialized() -> BTreeMap<AccountId, ShardData> {
    let mut states = BTreeMap::new();
    for (instruction, account) in [
        (Instruction::Initialize {}, catalog()),
        (Instruction::CreatePage { number: 0 }, page()),
    ] {
        let (input, request) = call(instruction, &[account], &states);
        execute(&input, &request, &mut states);
    }
    states
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
fn batch(count: u64, regions: &[&str]) -> Instruction {
    Instruction::RegisterBatch {
        number: 0,
        expected_count: count,
        timestamp: 100,
        snapshots_json: serde_json::to_string(
            &regions.iter().map(|r| snapshot(r)).collect::<Vec<_>>(),
        )
        .unwrap(),
    }
}

#[test]
fn spel_seed_addresses_match_v03_program_account_derivation() {
    let seed = old::seed_from_str("maps");
    assert_eq!(
        catalog(),
        AccountId::for_public_pda(&id(3), &PdaSeed::new(seed))
    );
    use old::ToSeed;
    use risc0_zkvm::sha::rust_crypto::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(old::seed_from_str("map-page"));
    hash.update(0u64.to_seed());
    assert_eq!(
        page(),
        AccountId::for_public_pda(&id(3), &PdaSeed::new(hash.finalize().into()))
    );
}

#[test]
fn initialize_and_batch_use_spel_validation_and_v03_effects() {
    let mut states = initialized();
    let (input, request) = call(
        batch(0, &["africa/ethiopia", "europe/germany"]),
        &[catalog(), page()],
        &states,
    );
    let output = plan(&input, &request).unwrap();
    assert_eq!(output.output().timestamp_validity_window.start(), Some(0));
    assert_eq!(
        output.output().timestamp_validity_window.end(),
        Some(300101)
    );
    execute(&input, &request, &mut states);
    let catalog: Catalog = borsh::from_slice(&states[&catalog()]).unwrap();
    let page: Page = borsh::from_slice(&states[&page()]).unwrap();
    assert_eq!(catalog.count, 2);
    assert_eq!(page.records.len(), 2);
    assert_eq!(page.records[1].ordinal, 1);
    assert_eq!(page.records[1].registrant, [7; 32]);
    assert!(
        plan(
            &input,
            &Request {
                states: vec![
                    states[&self::catalog()].clone(),
                    states[&self::page()].clone()
                ],
                ..request
            }
        )
        .is_err()
    );
}

#[test]
fn unauthorized_forged_duplicate_and_foreign_handles_fail() {
    let states = initialized();
    let (input, request) = call(
        batch(0, &["africa/ethiopia"]),
        &[catalog(), page()],
        &states,
    );
    for alteration in 0..4 {
        let mut bad = input.clone();
        match alteration {
            0 => bad.accounts[2].is_authorized = false,
            1 => bad.accounts[0].account_id = id(44),
            2 => bad.accounts[0].program_account_id = id(55),
            _ => bad.accounts[1] = bad.accounts[0].clone(),
        }
        assert!(plan(&bad, &request).is_err());
    }
    let (input, request) = call(Instruction::Initialize {}, &[catalog()], &states);
    assert!(plan(&input, &request).is_err());
}

#[test]
fn stale_state_and_effect_substitution_cannot_overwrite_shards() {
    let states = initialized();
    let (input, request) = call(
        batch(0, &["africa/ethiopia"]),
        &[catalog(), page()],
        &states,
    );
    let plan = plan(&input, &request).unwrap();
    for effect in &plan.output().effects {
        let call = ApplyInput {
            self_account_id: id(3),
            selector: effect.selector,
            pre_data: states[&effect.selector.account_id].clone(),
            effect_data: effect.data.clone(),
        };
        let mut changed = call.clone();
        let mut bytes = changed.pre_data.into_inner();
        bytes[0] ^= 1;
        changed.pre_data = bytes.try_into().unwrap();
        assert!(apply(changed).is_err());
        let mut foreign = call.clone();
        foreign.selector.program_account_id = id(99);
        assert!(apply(foreign).is_err());
        let mut substituted = call;
        substituted.self_account_id = id(88);
        assert!(apply(substituted).is_err());
    }
}

#[test]
fn invalid_batches_and_envelope_bounds_fail_closed() {
    let states = initialized();
    for regions in [
        vec![],
        vec!["africa/ethiopia"; 2],
        vec!["africa/ethiopia"; 9],
    ] {
        let (input, request) = call(batch(0, &regions), &[catalog(), page()], &states);
        assert!(plan(&input, &request).is_err());
    }
    let (_, request) = call(Instruction::Initialize {}, &[catalog()], &BTreeMap::new());
    let bytes = borsh::to_vec(&request).unwrap();
    assert!(borsh::from_slice::<Request>(&bytes).is_ok());
    let mut huge = bytes.clone();
    huge[2..6].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(borsh::from_slice::<Request>(&huge).is_err());
    let mut count = bytes;
    let offset = 6 + request.instruction_json.len();
    count[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(borsh::from_slice::<Request>(&count).is_err());
}
