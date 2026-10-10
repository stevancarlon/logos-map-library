// SPDX-License-Identifier: MIT OR Apache-2.0
//! v0.3 plan/apply adapter for the existing SPEL-generated map handlers.
//! Old account objects are local handler inputs only, never v0.3 wire accounts.
use borsh::{BorshDeserialize, BorshSerialize};
use lee_core_v03::{
    account::{AccountId, ShardData},
    program::{ApplyInput, ApplyOutput, Plan, PlanInput},
};
use logos_map_registry::{Instruction, map_registry as handlers};
use spel_framework::prelude as old;
use std::io::{self, Read};

pub use logos_map_registry::{Catalog, MAX_BATCH, PAGE_SIZE, Page, Record, Snapshot};
pub const ENVELOPE_VERSION: u16 = 1;
const MAX_INSTRUCTION_BYTES: usize = 20_000;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("SPEL map validation: {0}")]
    Spel(String),
}
pub type Result<T> = std::result::Result<T, Error>;

/// Borsh transport envelope around the SPEL-generated JSON instruction.
/// States correspond to catalog/page inputs; the authorized author is last.
#[derive(Clone, Debug, BorshSerialize)]
pub struct Request {
    pub version: u16,
    pub instruction_json: String,
    pub states: Vec<ShardData>,
}
impl BorshDeserialize for Request {
    fn deserialize_reader<R: Read>(reader: &mut R) -> io::Result<Self> {
        let version = u16::deserialize_reader(reader)?;
        let len = u32::deserialize_reader(reader)? as usize;
        if version != ENVELOPE_VERSION || len > MAX_INSTRUCTION_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid map envelope",
            ));
        }
        let mut bytes = vec![0; len];
        reader.read_exact(&mut bytes)?;
        let instruction_json = String::from_utf8(bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "map instruction UTF-8"))?;
        let count = u32::deserialize_reader(reader)?;
        if !(1..=2).contains(&count) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "map state count",
            ));
        }
        let mut states = Vec::with_capacity(count as usize);
        for _ in 0..count {
            states.push(ShardData::deserialize_reader(reader)?);
        }
        Ok(Self {
            version,
            instruction_json,
            states,
        })
    }
}

#[derive(BorshSerialize, BorshDeserialize)]
struct Mutation {
    registry: AccountId,
    account: AccountId,
    before: [u8; 32],
    after: ShardData,
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    use risc0_zkvm::sha::rust_crypto::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"logos-maps/v03/state/v1\0");
    hash.update(bytes);
    hash.finalize().into()
}

/// The pinned SPEL PDA implementation hashes the program's 32 raw bytes.
/// In this adapter those bytes name the v0.3 executable account, not its image.
pub fn spel_program_identity(registry: AccountId) -> [u32; 8] {
    std::array::from_fn(|i| {
        u32::from_le_bytes(registry.as_ref()[i * 4..i * 4 + 4].try_into().unwrap())
    })
}

pub fn plan(input: &PlanInput, request: &Request) -> Result<Plan> {
    if request.version != ENVELOPE_VERSION || request.instruction_json.len() > MAX_INSTRUCTION_BYTES
    {
        return Err(Error::Invalid("invalid map request envelope"));
    }
    let instruction: Instruction = serde_json::from_str(&request.instruction_json)
        .map_err(|_| Error::Invalid("invalid SPEL map instruction"))?;
    let writable = match &instruction {
        Instruction::RegisterBatch { .. } => 2,
        _ => 1,
    };
    if input.accounts.len() != writable + 1 || request.states.len() != writable {
        return Err(Error::Invalid("map account/state count mismatch"));
    }
    let author = &input.accounts[writable];
    if !author.is_authorized
        || input
            .accounts
            .iter()
            .any(|a| a.program_account_id != input.self_account_id)
    {
        return Err(Error::Invalid(
            "map inputs must select this registry; author must authorize",
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    if input.accounts.iter().any(|a| !seen.insert(a.account_id)) {
        return Err(Error::Invalid("duplicate map account"));
    }
    let identity = spel_program_identity(input.self_account_id);
    let mut accounts = Vec::with_capacity(input.accounts.len());
    for (index, meta) in input.accounts.iter().enumerate() {
        let mut account = old::Account::default();
        if let Some(state) = request.states.get(index) {
            if !state.is_empty() {
                account.program_owner = identity;
            }
            account.data = state
                .to_vec()
                .try_into()
                .map_err(|_| Error::Invalid("map state too large for SPEL"))?;
        }
        accounts.push(old::AccountWithMetadata {
            account_id: old::AccountId::new(meta.account_id.as_ref().try_into().unwrap()),
            account,
            is_authorized: meta.is_authorized,
        });
    }
    let map_error = |e: old::SpelError| Error::Spel(e.to_string());
    let words = vec![]; // Generated validators do not consume instruction words.
    let output = match instruction {
        Instruction::Initialize => {
            handlers::__validate_initialize(&accounts, &identity, &words).map_err(map_error)?;
            handlers::initialize(accounts[0].clone(), accounts[1].clone()).map_err(map_error)?
        }
        Instruction::CreatePage { number } => {
            handlers::__validate_create_page(&accounts, &identity, &words, &number)
                .map_err(map_error)?;
            handlers::create_page(accounts[0].clone(), accounts[1].clone(), number)
                .map_err(map_error)?
        }
        Instruction::RegisterBatch {
            number,
            expected_count,
            timestamp,
            snapshots_json,
        } => {
            handlers::__validate_register_batch(&accounts, &identity, &words, &number)
                .map_err(map_error)?;
            handlers::register_batch(
                accounts[0].clone(),
                accounts[1].clone(),
                accounts[2].clone(),
                number,
                expected_count,
                timestamp,
                snapshots_json,
            )
            .map_err(map_error)?
        }
    };
    if output.post_states.len() != accounts.len()
        || !output.chained_calls.is_empty()
        || output.block_validity_window.start().is_some()
        || output.block_validity_window.end().is_some()
    {
        return Err(Error::Invalid("unexpected SPEL map output"));
    }
    let mut result = Plan::new(input);
    match (
        output.timestamp_validity_window.start(),
        output.timestamp_validity_window.end(),
    ) {
        (Some(start), Some(end)) => {
            result.timestamp_window(
                lee_core_v03::program::TimestampValidityWindow::try_from(start..end)
                    .map_err(|_| Error::Invalid("invalid map timestamp window"))?,
            );
        }
        (None, None) => {}
        _ => return Err(Error::Invalid("unsupported map timestamp window")),
    }
    for index in 0..writable {
        let after: ShardData = output.post_states[index]
            .account()
            .data
            .as_ref()
            .to_vec()
            .try_into()
            .map_err(|_| Error::Invalid("map output exceeds v0.3 shard limit"))?;
        result.effect(
            &input.accounts[index],
            &Mutation {
                registry: input.self_account_id,
                account: input.accounts[index].account_id,
                before: digest(&request.states[index]),
                after,
            },
        );
    }
    Ok(result)
}

/// Runtime invokes each effect against actual chain state. A changed input
/// invalidates the transaction instead of overwriting a concurrent registration.
pub fn apply(input: ApplyInput) -> Result<ApplyOutput> {
    let mutation: Mutation =
        borsh::from_slice(&input.effect_data).map_err(|_| Error::Invalid("invalid map effect"))?;
    if mutation.registry != input.self_account_id
        || mutation.account != input.selector.account_id
        || input.selector.program_account_id != input.self_account_id
        || digest(&input.pre_data) != mutation.before
    {
        return Err(Error::Invalid("map state changed or effect substituted"));
    }
    Ok(ApplyOutput::new(input, Some(mutation.after)))
}

#[cfg(test)]
mod tests;
