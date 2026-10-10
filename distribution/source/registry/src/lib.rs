// SPDX-License-Identifier: MIT OR Apache-2.0
//! Registry account state and native SPEL handlers. No off-chain authority oracle.
use serde::{Deserialize, Serialize};
use spel_framework::prelude::*;

pub const PAGE_SIZE: usize = 128;
pub const SCHEMA: u16 = 1;

#[account_type]
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize, PartialEq)]
pub struct Metadata {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub tags: Vec<String>,
    pub idl_cid: String,
    pub source_cid: String,
    pub source_commit: String,
    /// Logos Storage pointer to reproducible build instructions; never executed implicitly.
    pub build_config_cid: String,
}

impl Metadata {
    pub fn validate(&self) -> Result<(), SpelError> {
        for (value, max, name) in [
            (&self.name, 80, "name"),
            (&self.version, 40, "version"),
            (&self.author, 120, "author"),
            (&self.description, 2048, "description"),
        ] {
            if value.trim().is_empty()
                || value.len() > max
                || value.chars().any(|c| c.is_control() && c != '\n')
            {
                return Err(SpelError::custom(1, format!("Invalid {name}")));
            }
        }
        for cid in [&self.idl_cid, &self.source_cid, &self.build_config_cid] {
            // A transport-independent identifier, not an HTTP URL or executable path.
            // Full multiformats validation belongs to the Logos Storage adapter.
            if cid.is_empty() || cid.len() > 128 || !cid.bytes().all(|c| c.is_ascii_alphanumeric())
            {
                return Err(SpelError::custom(2, "Invalid storage identifier"));
            }
        }
        if ![40, 64].contains(&self.source_commit.len())
            || !self.source_commit.bytes().all(|c| c.is_ascii_hexdigit())
        {
            return Err(SpelError::custom(
                3,
                "Source commit must be a full Git object ID",
            ));
        }
        if self.tags.len() > 8
            || self.tags.iter().any(|s| {
                s.is_empty()
                    || s.len() > 32
                    || !s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            })
        {
            return Err(SpelError::custom(4, "Invalid tags"));
        }
        Ok(())
    }
}

#[account_type]
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub schema: u16,
    pub program_id: [u8; 32],
    pub registrant: [u8; 32],
    pub ordinal: u64,
    pub revision: u64,
    /// Author-supplied Unix milliseconds, bounded to within five minutes of
    /// the block timestamp by the program output validity window.
    pub submitted_at: u64,
    pub metadata: Metadata,
}

#[account_type]
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct Catalog {
    pub schema: u16,
    pub count: u64,
}

#[account_type]
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct CatalogPage {
    pub schema: u16,
    pub number: u64,
    pub entries: Vec<[u8; 32]>,
}

fn decode<T: BorshDeserialize>(account: &AccountWithMetadata) -> Result<T, SpelError> {
    let bytes: Vec<u8> = account.account.data.clone().into();
    borsh::from_slice(&bytes).map_err(|e| SpelError::custom(5, e.to_string()))
}
fn encode<T: BorshSerialize>(
    account: &mut AccountWithMetadata,
    state: &T,
) -> Result<(), SpelError> {
    let bytes = borsh::to_vec(state).map_err(|e| SpelError::custom(6, e.to_string()))?;
    account.account.data = bytes
        .try_into()
        .map_err(|_| SpelError::custom(7, "Account data too large"))?;
    Ok(())
}
fn schema(schema: u16) -> Result<(), SpelError> {
    if schema != SCHEMA {
        return Err(SpelError::custom(8, "Unsupported schema"));
    }
    Ok(())
}

#[lez_program]
pub mod registry {
    #[allow(unused_imports)]
    use super::*;

    #[instruction]
    pub fn initialize(
        #[account(init, pda = literal("registry"))] mut catalog: AccountWithMetadata,
        #[account(signer)] payer: AccountWithMetadata,
    ) -> SpelResult {
        encode(
            &mut catalog,
            &Catalog {
                schema: SCHEMA,
                count: 0,
            },
        )?;
        Ok(SpelOutput::execute(vec![catalog, payer], vec![]))
    }

    /// Anyone can create a page, but its address and contents are deterministic.
    #[instruction]
    pub fn create_page(
        #[account(init, pda = [literal("page"), arg("number")])] mut page: AccountWithMetadata,
        #[account(signer)] payer: AccountWithMetadata,
        number: u64,
    ) -> SpelResult {
        encode(
            &mut page,
            &CatalogPage {
                schema: SCHEMA,
                number,
                entries: vec![],
            },
        )?;
        Ok(SpelOutput::execute(vec![page, payer], vec![]))
    }

    #[instruction]
    // SPEL exposes accounts and instruction arguments separately in the ABI.
    #[allow(clippy::too_many_arguments)]
    pub fn register(
        #[account(mut, owner = self_program_id, pda = literal("registry"))]
        mut catalog: AccountWithMetadata,
        #[account(mut, owner = self_program_id, pda = [literal("page"), arg("page_number")])]
        mut page: AccountWithMetadata,
        #[account(init, pda = [literal("entry"), arg("program_id"), account("author")])] mut entry: AccountWithMetadata,
        #[account(signer)] author: AccountWithMetadata,
        program_id: [u8; 32],
        page_number: u64,
        submitted_at: u64,
        metadata_json: String,
        claim_deployer: bool,
    ) -> SpelResult {
        // LEZ v0.2.4 deployment has no authenticated deployer. Fail closed.
        if claim_deployer {
            return Err(SpelError::custom(
                9,
                "Authenticated deployer evidence unavailable",
            ));
        }
        if program_id == [0; 32] {
            return Err(SpelError::custom(10, "Empty program ID"));
        }
        if metadata_json.len() > 8192 {
            return Err(SpelError::custom(11, "Metadata too large"));
        }
        let metadata: Metadata = serde_json::from_str(&metadata_json)
            .map_err(|e| SpelError::custom(12, e.to_string()))?;
        metadata.validate()?;
        let mut catalog_state: Catalog = decode(&catalog)?;
        let mut page_state: CatalogPage = decode(&page)?;
        schema(catalog_state.schema)?;
        schema(page_state.schema)?;
        if page_number != catalog_state.count / PAGE_SIZE as u64
            || page_state.number != page_number
            || page_state.entries.len() != (catalog_state.count % PAGE_SIZE as u64) as usize
        {
            return Err(SpelError::custom(
                13,
                "Stale or inconsistent catalog page; refetch before retry",
            ));
        }
        let state = Entry {
            schema: SCHEMA,
            program_id,
            registrant: *author.account_id.value(),
            ordinal: catalog_state.count,
            revision: 0,
            submitted_at,
            metadata,
        };
        catalog_state.count = catalog_state
            .count
            .checked_add(1)
            .ok_or_else(|| SpelError::custom(14, "Catalog full"))?;
        page_state.entries.push(*entry.account_id.value());
        encode(&mut entry, &state)?;
        encode(&mut page, &page_state)?;
        encode(&mut catalog, &catalog_state)?;
        let end = submitted_at
            .checked_add(300_001)
            .ok_or_else(|| SpelError::custom(18, "Timestamp overflow"))?;
        SpelOutput::execute(vec![catalog, page, entry, author], vec![])
            .try_with_timestamp_validity_window(submitted_at.saturating_sub(300_000)..end)
            .map_err(|e| SpelError::custom(19, e.to_string()))
    }

    #[instruction]
    pub fn update(
        #[account(mut, owner = self_program_id, pda = [literal("entry"), arg("program_id"), account("author")])]
        mut entry: AccountWithMetadata,
        #[account(signer)] author: AccountWithMetadata,
        program_id: [u8; 32],
        expected_revision: u64,
        metadata_json: String,
    ) -> SpelResult {
        let mut state: Entry = decode(&entry)?;
        schema(state.schema)?;
        if state.registrant != *author.account_id.value() || state.program_id != program_id {
            return Err(SpelError::custom(
                15,
                "Only the original registrant can update",
            ));
        }
        if state.revision != expected_revision {
            return Err(SpelError::custom(16, "Revision conflict"));
        }
        if metadata_json.len() > 8192 {
            return Err(SpelError::custom(11, "Metadata too large"));
        }
        let metadata: Metadata = serde_json::from_str(&metadata_json)
            .map_err(|e| SpelError::custom(12, e.to_string()))?;
        metadata.validate()?;
        state.metadata = metadata;
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or_else(|| SpelError::custom(17, "Revision overflow"))?;
        encode(&mut entry, &state)?;
        Ok(SpelOutput::execute(vec![entry, author], vec![]))
    }
}
