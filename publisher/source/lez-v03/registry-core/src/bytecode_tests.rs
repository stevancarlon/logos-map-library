// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::apply_guard;
use lee_core_v03::program::ProgramSegment;
use lee_core_v03::program::{AccountMeta, validate_apply_output, validate_plan};
use std::collections::BTreeMap;
// Synthetic ELF for image computation only, not a useful program or VM run.
fn elf() -> Vec<u8> {
    let mut bytes = vec![0; 88];
    bytes[..7].copy_from_slice(b"\x7fELF\x01\x01\x01");
    for (offset, value) in [(16, 2u16), (18, 243), (40, 52), (42, 32), (44, 1)] {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [
        (20, 1u32),
        (24, 0x00200400),
        (28, 52),
        (52, 1),
        (56, 84),
        (60, 0x00200400),
        (64, 0x00200400),
        (68, 4),
        (72, 4),
        (76, 5),
        (80, 4),
        (84, 0x00000073),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn id(n: u8) -> AccountId {
    AccountId::new([n; 32])
}
fn fixture() -> (PlanInput, DeploymentWitness, BTreeMap<AccountId, ShardData>) {
    let elf = elf();
    let image = risc0_binfmt::ProgramBinary::new(&elf, risc0_zkos_v1compat::V1COMPAT_ELF)
        .compute_image_id()
        .unwrap()
        .into();
    let header = ProgramHeader {
        image_id: image,
        program_first_segment: id(8),
        immutable: false,
    };
    let first: ShardData = ProgramSegment {
        bytecode: elf[..44].to_vec(),
        next_segment: Some(id(9)),
    }
    .to_bytes()
    .try_into()
    .unwrap();
    let last: ShardData = ProgramSegment {
        bytecode: elf[44..].to_vec(),
        next_segment: None,
    }
    .to_bytes()
    .try_into()
    .unwrap();
    let input = PlanInput {
        self_account_id: id(3),
        caller_account_id: None,
        instruction_data: vec![],
        accounts: vec![
            AccountMeta::new(id(4), true, id(3)),
            AccountMeta::new(id(4), true, PROGRAM_LOADER_ACCOUNT_ID),
            AccountMeta::new(id(8), false, PROGRAM_LOADER_ACCOUNT_ID),
            AccountMeta::new(id(9), false, PROGRAM_LOADER_ACCOUNT_ID),
        ],
    };
    let witness = DeploymentWitness {
        header,
        segments: vec![
            SegmentWitness {
                input_index: 2,
                shard: first.clone(),
            },
            SegmentWitness {
                input_index: 3,
                shard: last.clone(),
            },
        ],
    };
    let states = BTreeMap::from([
        (id(4), header.to_bytes().try_into().unwrap()),
        (id(8), first),
        (id(9), last),
    ]);
    (input, witness, states)
}
fn plan(input: &PlanInput, witness: &DeploymentWitness) -> Result<Plan> {
    bytecode_registration_plan(
        input,
        0,
        1,
        witness.header.image_id,
        Claim::HeaderAccountAuthorized,
        witness,
    )
}
fn execute(plan: &Plan, states: &BTreeMap<AccountId, ShardData>) -> Result<()> {
    validate_plan(&plan.output().input, plan.output()).unwrap();
    for effect in &plan.output().effects {
        let input = ApplyInput {
            self_account_id: plan.output().input.self_account_id,
            selector: effect.selector,
            pre_data: states[&effect.selector.account_id].clone(),
            effect_data: effect.data.clone(),
        };
        let output = apply_guard(input.clone())?;
        assert!(output.post_data.is_none());
        validate_apply_output(&input, &output).unwrap();
    }
    Ok(())
}
#[test]
fn verified_image_plan_binds_header_and_all_segments_without_foreign_writes() {
    let (input, witness, states) = fixture();
    let plan = plan(&input, &witness).unwrap();
    assert_eq!(plan.output().effects.len(), 3);
    execute(&plan, &states).unwrap();
    for account in [id(4), id(8), id(9)] {
        let mut changed = states.clone();
        let mut bytes = changed[&account].clone().into_inner();
        bytes[0] ^= 1;
        changed.insert(account, bytes.try_into().unwrap());
        assert!(execute(&plan, &changed).is_err());
    }
    // Even a header update retaining the same image must invalidate this plan.
    let mut changed = states;
    let mut header = witness.header;
    header.immutable = true;
    changed.insert(id(4), header.to_bytes().try_into().unwrap());
    assert!(execute(&plan, &changed).is_err());
}
#[test]
fn witness_rejects_wrong_images_links_cycles_truncation_and_missing_selectors() {
    let (input, witness, _) = fixture();
    let mut changed = witness.clone();
    changed.segments.swap(0, 1);
    assert!(plan(&input, &changed).is_err());
    let mut changed = witness.clone();
    changed.segments.pop();
    assert!(plan(&input, &changed).is_err());
    let mut changed = witness.clone();
    changed.segments[0].input_index = 99;
    assert!(plan(&input, &changed).is_err());
    let mut changed = witness.clone();
    changed.header.image_id[0] ^= 1;
    assert!(plan(&input, &changed).is_err());
    let mut changed = witness.clone();
    changed.header.program_first_segment = id(9);
    assert!(plan(&input, &changed).is_err());
    let mut changed = witness.clone();
    let mut segment = ProgramSegment::from_bytes(&changed.segments[1].shard).unwrap();
    segment.next_segment = Some(id(8));
    changed.segments[1].shard = segment.to_bytes().try_into().unwrap();
    assert!(plan(&input, &changed).is_err());
    let mut changed = witness.clone();
    let mut segment = ProgramSegment::from_bytes(&changed.segments[1].shard).unwrap();
    *segment.bytecode.last_mut().unwrap() ^= 1;
    changed.segments[1].shard = segment.to_bytes().try_into().unwrap();
    assert!(plan(&input, &changed).is_err());
    let mut changed = input;
    changed.accounts[2].program_account_id = id(3);
    assert!(plan(&changed, &witness).is_err());
}
#[test]
fn segment_shaped_header_is_rejected_when_its_claimed_image_is_not_the_linked_elf() {
    let (input, mut witness, _) = fixture();
    let ambiguous = ProgramSegment {
        bytecode: vec![8; 60],
        next_segment: None,
    }
    .to_bytes();
    witness.header = ProgramHeader::from_bytes(&ambiguous).unwrap();
    assert_eq!(witness.header.program_first_segment, id(8));
    assert!(plan(&input, &witness).is_err());
}
#[test]
fn witness_decoding_bounds_segment_count_and_each_shard_before_allocation() {
    let (_, witness, _) = fixture();
    let encoded = borsh::to_vec(&witness).unwrap();
    assert!(borsh::from_slice::<DeploymentWitness>(&encoded).is_ok());
    for count in [0u32, 21, u32::MAX] {
        let mut bytes = witness.header.to_bytes();
        bytes.extend(count.to_le_bytes());
        assert!(borsh::from_slice::<DeploymentWitness>(&bytes).is_err());
    }
    let mut bytes = witness.header.to_bytes();
    bytes.extend(1u32.to_le_bytes());
    bytes.extend(2u16.to_le_bytes());
    bytes.extend(u32::MAX.to_le_bytes());
    assert!(borsh::from_slice::<DeploymentWitness>(&bytes).is_err());
}

#[test]
fn borrowed_segment_parser_matches_upstream_and_rejects_trailing_or_truncated_data() {
    for length in [0, 1, 3, 4, 90_000] {
        for next_segment in [None, Some(id(5))] {
            let value = ProgramSegment {
                bytecode: vec![7; length],
                next_segment,
            };
            let bytes = value.to_bytes();
            let (body, next) = segment_parts(&bytes).unwrap();
            assert_eq!(body, value.bytecode);
            assert_eq!(next, next_segment);
            for cut in [0, 3, bytes.len() - 1] {
                assert!(segment_parts(&bytes[..cut]).is_err());
            }
            let mut extra = bytes.clone();
            extra.push(0);
            assert!(segment_parts(&extra).is_err());
        }
    }
    assert!(segment_parts(&[255, 255, 255, 255, 0]).is_err());
    assert!(segment_parts(&[0, 0, 0, 0, 2]).is_err());
}
