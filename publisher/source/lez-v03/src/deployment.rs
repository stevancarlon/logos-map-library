// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bounded loader observations, not independent chain or source verification.
use crate::{AccountId, AccountView, Error, Node, Result, ShardSelector};
use lee_core_v03::program::{MAX_PROGRAM_SEGMENTS, ProgramHeader, ProgramSegment};
use serde::Serialize;
use std::collections::BTreeSet;

pub const LOADER: AccountId = AccountId::from_bytes([0xfe; 32]);

pub trait DeploymentReader {
    fn loader_view(&self, account: AccountId) -> Result<AccountView>;
}
impl DeploymentReader for Node {
    fn loader_view(&self, account: AccountId) -> Result<AccountView> {
        self.account_view(&ShardSelector {
            account_id: account,
            program_account_id: LOADER,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct DeploymentObservation {
    pub program_account: AccountId,
    pub image_id: [u32; 8],
    pub immutable: bool,
    pub segments: Vec<AccountId>,
    pub user_elf_bytes: usize,
    pub header_nonce: String,
}

fn shard(view: &AccountView, account: AccountId) -> Result<&[u8]> {
    view.validate_projection(&ShardSelector {
        account_id: account,
        program_account_id: LOADER,
    })?;
    view.data
        .shards
        .get(&LOADER)
        .map(Vec::as_slice)
        .filter(|bytes| !bytes.is_empty())
        .ok_or(Error::Invalid("missing loader shard"))
}

/// Recompute the pinned image, then re-read the header to catch concurrent updates.
/// The caller must supply the expected image from its reviewed context. This
/// does not establish an original human deployer, source reproducibility or finality.
/// Reads are not a historical snapshot; revalidate immediately before signing.
pub fn inspect(
    reader: &impl DeploymentReader,
    account: AccountId,
    expected_image: [u32; 8],
) -> Result<DeploymentObservation> {
    if account == crate::NATIVE_PROGRAM || account == LOADER {
        return Err(Error::Invalid("native dispatch has no deployed guest"));
    }
    let before = reader.loader_view(account)?;
    let header_bytes = shard(&before, account)?;
    let header =
        ProgramHeader::from_bytes(header_bytes).ok_or(Error::Invalid("invalid program header"))?;
    if header.image_id != expected_image {
        return Err(Error::Invalid("program header differs from reviewed image"));
    }
    let mut visited = BTreeSet::from([account]);
    let mut segments = Vec::new();
    let mut elf = Vec::new();
    let mut next = Some(header.program_first_segment);
    while let Some(id) = next {
        let id = AccountId::from_bytes(*id.value());
        if segments.len() == MAX_PROGRAM_SEGMENTS || !visited.insert(id) {
            return Err(Error::Invalid("cyclic or oversized segment chain"));
        }
        let view = reader.loader_view(id)?;
        let segment = ProgramSegment::from_bytes(shard(&view, id)?)
            .ok_or(Error::Invalid("invalid program segment"))?;
        // Each projection is bounded before decoding, and the chain has a hard cap.
        elf.extend_from_slice(&segment.bytecode);
        segments.push(id);
        next = segment.next_segment;
    }
    let binary = risc0_binfmt::ProgramBinary::new(&elf, risc0_zkos_v1compat::V1COMPAT_ELF);
    let computed: [u32; 8] = binary
        .compute_image_id()
        .map_err(|_| Error::Invalid("invalid deployed ELF"))?
        .into();
    if computed != expected_image {
        return Err(Error::Invalid(
            "deployed bytecode differs from reviewed image",
        ));
    }
    let after = reader.loader_view(account)?;
    if shard(&after, account)? != header_bytes || after.nonce != before.nonce {
        return Err(Error::Invalid("program header changed during inspection"));
    }
    Ok(DeploymentObservation {
        program_account: account,
        image_id: computed,
        immutable: header.immutable,
        segments,
        user_elf_bytes: elf.len(),
        header_nonce: before.nonce.to_string(),
    })
}
