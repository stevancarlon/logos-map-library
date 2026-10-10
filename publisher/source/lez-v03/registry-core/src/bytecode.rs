// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bind a reviewed ELF image to every loader shard in the same registry plan.
use crate::{Claim, Error, Guard, Result, authority::validate_registration};
use borsh::{BorshDeserialize, BorshSerialize};
use lee_core_v03::{
    account::{AccountId, ShardData},
    program::{
        ApplyInput, ApplyOutput, MAX_PROGRAM_SEGMENTS, PROGRAM_LOADER_ACCOUNT_ID, Plan, PlanInput,
        ProgramHeader, ProgramId,
    },
};
#[cfg(not(target_os = "zkvm"))]
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{self, Read},
};

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct SegmentWitness {
    pub input_index: u16,
    // Upstream ShardData bounds deserialization before allocation.
    pub shard: ShardData,
}
#[derive(Clone, Debug, BorshSerialize)]
pub struct DeploymentWitness {
    pub header: ProgramHeader,
    pub segments: Vec<SegmentWitness>,
}
impl BorshDeserialize for DeploymentWitness {
    fn deserialize_reader<R: Read>(reader: &mut R) -> io::Result<Self> {
        let header = ProgramHeader::deserialize_reader(reader)?;
        let count = u32::deserialize_reader(reader)? as usize;
        if count == 0 || count > MAX_PROGRAM_SEGMENTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid deployment segment count",
            ));
        }
        let mut segments = Vec::with_capacity(count);
        for _ in 0..count {
            segments.push(SegmentWitness::deserialize_reader(reader)?);
        }
        Ok(Self { header, segments })
    }
}
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct ShardGuard {
    registry: AccountId,
    target: AccountId,
    digest: [u8; 32],
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    #[cfg(target_os = "zkvm")]
    use risc0_zkvm::sha::rust_crypto::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"logos-registry-v03/loader-shard/v1\0");
    hash.update(bytes);
    hash.finalize().into()
}

// Decode the same Borsh fields as ProgramSegment, retaining a bounded slice
// rather than allocating a second full copy of each shard's bytecode.
fn segment_parts(bytes: &[u8]) -> Result<(&[u8], Option<AccountId>)> {
    let invalid = || Error::Invalid("invalid deployment segment encoding");
    let mut rest = bytes;
    let len = u32::deserialize_reader(&mut rest).map_err(|_| invalid())? as usize;
    if len > rest.len() {
        return Err(invalid());
    }
    let (bytecode, mut tail) = rest.split_at(len);
    let next = Option::<AccountId>::deserialize_reader(&mut tail).map_err(|_| invalid())?;
    if !tail.is_empty() {
        return Err(invalid());
    }
    Ok((bytecode, next))
}

/// Checks the exact pinned image of the supplied linked bytecode, then emits
/// read guards tying those supplied bytes to actual chain state at apply time.
/// The registry must add its own entry/catalog writes to this same atomic plan.
/// This proves neither source reproducibility nor a historical human deployer.
pub fn bytecode_registration_plan(
    input: &PlanInput,
    author_index: usize,
    program_index: usize,
    expected_image: ProgramId,
    claim: Claim,
    witness: &DeploymentWitness,
) -> Result<Plan> {
    validate_registration(input, author_index, program_index, expected_image, claim)?;
    let mut plan = Plan::new(input);
    if witness.header.image_id != expected_image
        || witness.segments.is_empty()
        || witness.segments.len() > MAX_PROGRAM_SEGMENTS
    {
        return Err(Error::Invalid(
            "deployment witness image or segment count differs",
        ));
    }
    let program = &input.accounts[program_index];
    let mut seen = BTreeSet::from([program.account_id]);
    let mut next = Some(witness.header.program_first_segment);
    // Upper bound includes small segment headers; allocate once instead of
    // repeatedly copying already-collected ELF bytes as the buffer grows.
    let mut elf = Vec::with_capacity(witness.segments.iter().map(|s| s.shard.len()).sum());
    for segment in &witness.segments {
        let account = input
            .accounts
            .get(usize::from(segment.input_index))
            .ok_or(Error::Invalid("deployment segment input missing"))?;
        if account.program_account_id != PROGRAM_LOADER_ACCOUNT_ID
            || Some(account.account_id) != next
            || !seen.insert(account.account_id)
        {
            return Err(Error::Invalid(
                "deployment chain selector/order/cycle mismatch",
            ));
        }
        let (bytecode, next_segment) = segment_parts(&segment.shard)?;
        elf.extend_from_slice(bytecode);
        next = next_segment;
        let shard_digest = digest(&segment.shard);
        plan.inspect(
            account,
            PROGRAM_LOADER_ACCOUNT_ID,
            &Guard::Shard(ShardGuard {
                registry: input.self_account_id,
                target: account.account_id,
                digest: shard_digest,
            }),
        );
    }
    if next.is_some() {
        return Err(Error::Invalid("deployment chain was truncated"));
    }
    let computed: [u32; 8] =
        risc0_binfmt::ProgramBinary::new(&elf, risc0_zkos_v1compat::V1COMPAT_ELF)
            .compute_image_id()
            .map_err(|_| Error::Invalid("deployment witness is not a valid guest ELF"))?
            .into();
    if computed != expected_image {
        return Err(Error::Invalid(
            "deployment bytecode does not match the reviewed image",
        ));
    }
    plan.inspect(
        program,
        PROGRAM_LOADER_ACCOUNT_ID,
        &Guard::Shard(ShardGuard {
            registry: input.self_account_id,
            target: program.account_id,
            digest: digest(&witness.header.to_bytes()),
        }),
    );
    Ok(plan)
}

pub fn apply_shard_guard(input: ApplyInput) -> Result<ApplyOutput> {
    let Guard::Shard(guard) = borsh::from_slice::<Guard>(&input.effect_data)
        .map_err(|_| Error::Invalid("invalid registry shard guard"))?
    else {
        return Err(Error::Invalid("expected registry shard guard"));
    };
    if input.self_account_id != guard.registry
        || input.selector.account_id != guard.target
        || input.selector.program_account_id != PROGRAM_LOADER_ACCOUNT_ID
        || digest(&input.pre_data) != guard.digest
    {
        return Err(Error::Invalid(
            "deployment shard changed or was substituted",
        ));
    }
    Ok(ApplyOutput::new(input, None))
}

#[cfg(test)]
#[path = "bytecode_tests.rs"]
mod tests;
