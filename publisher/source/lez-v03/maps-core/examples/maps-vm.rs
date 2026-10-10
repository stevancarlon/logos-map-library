// SPDX-License-Identifier: MIT OR Apache-2.0
//! Synthetic state transitions under real r0vm, not deployment or hosting evidence.
use anyhow::{Result, bail, ensure};
use lee_core_v03::{
    account::{AccountId, ShardData},
    from_frame,
    program::{
        AccountMeta, ApplyInput, CallKind, GuestOutput, PlanInput, validate_apply_output,
        validate_plan,
    },
    to_borsh_frame,
};
use logos_map_registry::Instruction;
use logos_maps_v03_core::{
    Catalog, ENVELOPE_VERSION, Page, Request, Snapshot, spel_program_identity,
};
use risc0_zkvm::{ExecutorEnv, ExitCode, default_executor};
use spel_framework::prelude as old;
use std::collections::BTreeMap;

fn id(n: u8) -> AccountId {
    AccountId::new([n; 32])
}
fn pda(seeds: &[&[u8; 32]]) -> AccountId {
    AccountId::new(*old::compute_pda(&spel_program_identity(id(3)), seeds).value())
}
fn execute<T: borsh::BorshSerialize>(
    binary: &[u8],
    kind: CallKind,
    input: &T,
) -> Result<(GuestOutput, u64)> {
    let env = ExecutorEnv::builder()
        .write_slice(&to_borsh_frame(&kind))
        .write_slice(&to_borsh_frame(input))
        .session_limit(Some(20_000_000))
        .build()?;
    let session = default_executor().execute(env, binary)?;
    ensure!(
        session.exit_code == ExitCode::Halted(0),
        "Guest exit failure"
    );
    let bytes = &session.journal.bytes;
    let frame = from_frame(bytes).ok_or_else(|| anyhow::anyhow!("Missing output frame"))?;
    ensure!(frame.len() + 4 == bytes.len(), "Trailing guest output");
    Ok((borsh::from_slice(frame)?, session.cycles()))
}
fn rejected(result: Result<(GuestOutput, u64)>, reason: &str) -> Result<()> {
    let error = match result {
        Ok(_) => bail!("Forbidden call accepted: {reason}"),
        Err(e) => e,
    };
    ensure!(
        format!("{error:#}").contains(reason),
        "Unexpected failure: {error:#}"
    );
    Ok(())
}
fn call(
    instruction: Instruction,
    ids: &[AccountId],
    states: &BTreeMap<AccountId, ShardData>,
) -> Result<(PlanInput, Request)> {
    let request = Request {
        version: ENVELOPE_VERSION,
        instruction_json: serde_json::to_string(&instruction)?,
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
            .map(|a| AccountMeta::new(*a, false, id(3)))
            .chain([AccountMeta::new(id(7), true, id(3))])
            .collect(),
        instruction_data: borsh::to_vec(&request)?,
    };
    Ok((input, request))
}
fn transition(
    binary: &[u8],
    input: &PlanInput,
    request: &Request,
    states: &mut BTreeMap<AccountId, ShardData>,
    label: &str,
) -> Result<serde_json::Value> {
    let (out, cycles) = execute(binary, CallKind::Plan, input)?;
    let GuestOutput::Plan(plan) = out else {
        bail!("Expected plan");
    };
    validate_plan(input, &plan)?;
    ensure!(
        borsh::to_vec(&plan)?
            == borsh::to_vec(logos_maps_v03_core::plan(input, request)?.output())?,
        "Host/guest plan differs"
    );
    let mut staged = states.clone();
    let mut costs = vec![];
    for effect in &plan.effects {
        let apply = ApplyInput {
            self_account_id: input.self_account_id,
            selector: effect.selector,
            pre_data: states
                .get(&effect.selector.account_id)
                .cloned()
                .unwrap_or_default(),
            effect_data: effect.data.clone(),
        };
        let (out, cycles) = execute(binary, CallKind::Apply, &apply)?;
        let GuestOutput::Apply(result) = out else {
            bail!("Expected apply");
        };
        validate_apply_output(&apply, &result)?;
        ensure!(
            borsh::to_vec(&result)? == borsh::to_vec(&logos_maps_v03_core::apply(apply.clone())?)?,
            "Host/guest apply differs"
        );
        staged.insert(effect.selector.account_id, result.post_data.unwrap());
        costs.push(cycles);
        let mut stale = apply;
        stale.pre_data = vec![0xff].try_into()?;
        rejected(
            execute(binary, CallKind::Apply, &stale),
            "map state changed or effect substituted",
        )?;
    }
    *states = staged;
    Ok(serde_json::json!({"operation":label,"plan_cycles":cycles,"apply_cycles":costs}))
}
fn main() -> Result<()> {
    ensure!(
        std::env::var("RISC0_EXECUTOR").as_deref() == Ok("ipc")
            && std::env::var("RISC0_DEV_MODE").as_deref() == Ok("0"),
        "Real IPC execution required"
    );
    let guest = std::fs::read(
        std::env::args()
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("Usage: maps-vm GUEST_ELF"))?,
    )?;
    let binary =
        risc0_binfmt::ProgramBinary::new(&guest, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
    use old::ToSeed;
    let catalog = pda(&[&old::seed_from_str("maps")]);
    let page = pda(&[&old::seed_from_str("map-page"), &0u64.to_seed()]);
    let mut states = BTreeMap::new();
    let mut operations = vec![];
    for (instruction, account, label) in [
        (Instruction::Initialize {}, catalog, "initialize"),
        (Instruction::CreatePage { number: 0 }, page, "create_page"),
    ] {
        let (input, request) = call(instruction, &[account], &states)?;
        operations.push(transition(&binary, &input, &request, &mut states, label)?);
        let mut unsigned = input;
        unsigned.accounts[1].is_authorized = false;
        rejected(
            execute(&binary, CallKind::Plan, &unsigned),
            "author must authorize",
        )?;
    }
    for (count, size, label) in [(0u64, 1usize, "register"), (1, 8, "batch_register_8")] {
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
        let (input, request) = call(
            Instruction::RegisterBatch {
                number: 0,
                expected_count: count,
                timestamp: 100,
                snapshots_json: serde_json::to_string(&snapshots)?,
            },
            &[catalog, page],
            &states,
        )?;
        let mut forged = input.clone();
        forged.accounts[0].account_id = id(44);
        rejected(
            execute(&binary, CallKind::Plan, &forged),
            "map plan validation failed",
        )?;
        let mut unsigned = input.clone();
        unsigned.accounts[2].is_authorized = false;
        rejected(
            execute(&binary, CallKind::Plan, &unsigned),
            "author must authorize",
        )?;
        operations.push(transition(&binary, &input, &request, &mut states, label)?);
    }
    let final_catalog: Catalog = borsh::from_slice(&states[&catalog])?;
    let final_page: Page = borsh::from_slice(&states[&page])?;
    ensure!(final_catalog.count == 9 && final_page.records.len() == 9);
    for (i, record) in final_page.records.iter().enumerate() {
        ensure!(
            record.ordinal == i as u64 && record.registrant == [7; 32] && record.timestamp == 100
        );
    }
    println!(
        "{}",
        serde_json::json!({"result":"passed","execution":"real-r0vm","operations":operations,
        "records":9,"host_guest_exact_match":true,"changed_state_rejected":true,"unauthorized_rejected":true,"forged_pda_rejected":true})
    );
    Ok(())
}
