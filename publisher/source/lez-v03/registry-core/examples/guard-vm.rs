// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real r0vm execution of guard-stage plan/apply, not sequencer or final registry evidence.
use anyhow::{Result, bail, ensure};
use lee_core_v03::{
    account::{AccountId, ShardData},
    from_frame,
    program::{
        AccountMeta, ApplyInput, CallKind, GuestOutput, PlanInput, ProgramHeader, ProgramSegment,
        validate_apply_output, validate_plan,
    },
    to_borsh_frame,
};
use logos_registry_v03_core::{Claim, DeploymentWitness, GuardRequest, SegmentWitness};
use risc0_zkvm::{ExecutorEnv, ExitCode, default_executor};
use std::collections::BTreeMap;
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

fn execute<T: borsh::BorshSerialize>(
    binary: &[u8],
    kind: CallKind,
    input: &T,
) -> Result<(GuestOutput, u64)> {
    let env = ExecutorEnv::builder()
        .write_slice(&to_borsh_frame(&kind))
        .write_slice(&to_borsh_frame(input))
        .session_limit(Some(200_000_000))
        .build()?;
    let session = default_executor().execute(env, binary)?;
    ensure!(
        session.exit_code == ExitCode::Halted(0),
        "Guest did not exit successfully"
    );
    let bytes = &session.journal.bytes;
    let frame = from_frame(bytes).ok_or_else(|| anyhow::anyhow!("Missing guest frame"))?;
    ensure!(frame.len() + 4 == bytes.len(), "Trailing guest output");
    Ok((borsh::from_slice(frame)?, session.cycles()))
}
fn rejected(result: Result<(GuestOutput, u64)>, reason: &str) -> Result<()> {
    let error = match result {
        Ok(_) => bail!("Guest accepted a forbidden call: {reason}"),
        Err(error) => error,
    };
    ensure!(
        format!("{error:#}").contains(reason),
        "Unexpected guest failure: {error:#}"
    );
    Ok(())
}
fn main() -> Result<()> {
    ensure!(
        std::env::var("RISC0_EXECUTOR").as_deref() == Ok("ipc")
            && std::env::var("RISC0_DEV_MODE").as_deref() == Ok("0"),
        "Use real local IPC execution and RISC0_DEV_MODE=0"
    );
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("Usage: guard-vm GUEST_ELF"))?;
    let guest = std::fs::read(path)?;
    let binary =
        risc0_binfmt::ProgramBinary::new(&guest, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
    let target_path = std::env::args().nth(2);
    let target = if let Some(path) = &target_path {
        let bytes = std::fs::read(path)?;
        if bytes.starts_with(b"\x7fELF") {
            bytes
        } else {
            risc0_binfmt::ProgramBinary::decode(&bytes)?
                .user_elf
                .to_vec()
        }
    } else {
        elf()
    };
    let reject_invalid = std::env::args().nth(3).as_deref() == Some("--reject-invalid");
    let computed = risc0_binfmt::ProgramBinary::new(&target, risc0_zkos_v1compat::V1COMPAT_ELF)
        .compute_image_id();
    let image = if reject_invalid {
        ensure!(computed.is_err(), "Negative fixture is a valid host ELF");
        [123; 8]
    } else {
        computed?.into()
    };
    let id = |n| AccountId::new([n; 32]);
    let loader = lee_core_v03::program::PROGRAM_LOADER_ACCOUNT_ID;
    let header = ProgramHeader {
        image_id: image,
        program_first_segment: id(8),
        immutable: false,
    };
    let chunk_size = if target.len() <= 88 { 44 } else { 90_000 };
    let chunks: Vec<_> = target.chunks(chunk_size).collect();
    ensure!(chunks.len() <= lee_core_v03::program::MAX_PROGRAM_SEGMENTS);
    let shards: Vec<ShardData> = chunks
        .iter()
        .enumerate()
        .map(|(i, bytes)| {
            ProgramSegment {
                bytecode: bytes.to_vec(),
                next_segment: (i + 1 < chunks.len()).then(|| id(9 + i as u8)),
            }
            .to_bytes()
            .try_into()
            .unwrap()
        })
        .collect();
    let request = GuardRequest {
        author_index: 0,
        program_index: 1,
        expected_image: image,
        claim: Claim::HeaderAccountAuthorized,
        witness: DeploymentWitness {
            header,
            segments: shards
                .iter()
                .enumerate()
                .map(|(i, shard)| SegmentWitness {
                    input_index: (i + 2) as u16,
                    shard: shard.clone(),
                })
                .collect(),
        },
    };
    let input = PlanInput {
        self_account_id: id(3),
        caller_account_id: None,
        accounts: [
            AccountMeta::new(id(4), true, id(3)),
            AccountMeta::new(id(4), true, loader),
        ]
        .into_iter()
        .chain(
            shards
                .iter()
                .enumerate()
                .map(|(i, _)| AccountMeta::new(id(8 + i as u8), false, loader)),
        )
        .collect(),
        instruction_data: borsh::to_vec(&request)?,
    };
    let states: BTreeMap<_, ShardData> = std::iter::once((id(4), header.to_bytes().try_into()?))
        .chain(
            shards
                .iter()
                .enumerate()
                .map(|(i, shard)| (id(8 + i as u8), shard.clone())),
        )
        .collect();
    if reject_invalid {
        rejected(
            execute(&binary, CallKind::Plan, &input),
            "deployment witness is not a valid guest ELF",
        )?;
        println!(
            "{}",
            serde_json::json!({"result":"passed", "execution":"real-r0vm", "rejected_invalid_elf":true})
        );
        return Ok(());
    }
    let (output, plan_cycles) = execute(&binary, CallKind::Plan, &input)?;
    let GuestOutput::Plan(plan) = output else {
        bail!("Expected plan output")
    };
    validate_plan(&input, &plan)?;
    let host_plan = logos_registry_v03_core::bytecode_registration_plan(
        &input,
        0,
        1,
        image,
        request.claim,
        &request.witness,
    )?;
    ensure!(
        borsh::to_vec(host_plan.output())? == borsh::to_vec(&plan)?,
        "Guest guards differ from independent host SHA/image calculations"
    );
    ensure!(plan.effects.len() == shards.len() + 1);
    let mut apply_cycles = Vec::new();
    for effect in &plan.effects {
        let call = ApplyInput {
            self_account_id: input.self_account_id,
            selector: effect.selector,
            pre_data: states[&effect.selector.account_id].clone(),
            effect_data: effect.data.clone(),
        };
        let (output, cycles) = execute(&binary, CallKind::Apply, &call)?;
        let GuestOutput::Apply(applied) = output else {
            bail!("Expected apply output")
        };
        validate_apply_output(&call, &applied)?;
        ensure!(applied.post_data.is_none());
        apply_cycles.push(cycles);
    }
    let mut unsigned = input.clone();
    unsigned.accounts[0].is_authorized = false;
    rejected(
        execute(&binary, CallKind::Plan, &unsigned),
        "registry author must authorize its registry shard",
    )?;
    let effect = &plan.effects[0];
    let mut changed = states[&effect.selector.account_id].clone().into_inner();
    changed[0] ^= 1;
    let changed = ApplyInput {
        self_account_id: input.self_account_id,
        selector: effect.selector,
        pre_data: changed.try_into()?,
        effect_data: effect.data.clone(),
    };
    rejected(
        execute(&binary, CallKind::Apply, &changed),
        "deployment shard changed or was substituted",
    )?;
    let mut wrong = request;
    wrong.expected_image[0] ^= 1;
    wrong.witness.header.image_id = wrong.expected_image;
    let mut bad = input;
    bad.instruction_data = borsh::to_vec(&wrong)?;
    rejected(
        execute(&binary, CallKind::Plan, &bad),
        "deployment bytecode does not match the reviewed image",
    )?;
    println!(
        "{}",
        serde_json::json!({"result":"passed","execution":"real-r0vm","target_path":target_path,"target_bytes":target.len(),"guard_cycles":plan_cycles + apply_cycles.iter().sum::<u64>(),"fits_action_cap_before_registry_writes":plan_cycles + apply_cycles.iter().sum::<u64>() < 10_000_000,"plan_cycles":plan_cycles,"apply_cycles":apply_cycles,"host_computed_target_image":image,"guest_image":risc0_binfmt::compute_image_id(&binary)?.to_string(),"scope":"Real guest plan/apply with host-image equivalence for the supplied ELF (synthetic by default); unsigned, substituted-state and mismatched-image cases rejected. No registry entry, sequencer transaction, proof receipt or deployment."})
    );
    Ok(())
}
