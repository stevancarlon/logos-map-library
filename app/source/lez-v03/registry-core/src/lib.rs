// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared v0.3 registry planning/apply rules, without wallet, HTTP or SQLite dependencies.
//! Full SPEL integration and registry storage handlers remain under development.
mod authority;
mod bytecode;
pub use authority::*;
pub use bytecode::*;

/// Test-guest request for the guard stage, not the registry's final SPEL ABI.
#[derive(Clone, Debug, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct GuardRequest {
    pub author_index: u16,
    pub program_index: u16,
    pub expected_image: lee_core_v03::program::ProgramId,
    pub claim: Claim,
    pub witness: DeploymentWitness,
}

#[derive(Clone, Debug, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum Guard {
    Header(HeaderGuard),
    Shard(ShardGuard),
}

pub fn apply_guard(
    input: lee_core_v03::program::ApplyInput,
) -> Result<lee_core_v03::program::ApplyOutput> {
    match borsh::from_slice::<Guard>(&input.effect_data)
        .map_err(|_| Error::Invalid("invalid registry guard"))?
    {
        Guard::Header(_) => apply_header_guard(input),
        Guard::Shard(_) => apply_shard_guard(input),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(&'static str),
}
pub type Result<T> = std::result::Result<T, Error>;
