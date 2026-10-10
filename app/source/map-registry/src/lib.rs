// SPDX-License-Identifier: MIT OR Apache-2.0
//! Append-only, signer-attributed map snapshot announcements.
//! A registration is a hosting assertion, not a cryptographic proof of Geofabrik origin.
use serde::{Deserialize, Serialize};
use spel_framework::prelude::*;
pub mod regions;
pub const SCHEMA: u16 = 1;
pub const PAGE_SIZE: usize = 64;
pub const MAX_BATCH: usize = 8;
#[account_type]
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Snapshot {
    pub region: String,
    pub parent: Option<String>,
    pub level: String,
    pub cid: String,
    pub source_url: String,
    pub checksum: [u8; 16],
    pub sha256: [u8; 32],
    pub bytes: u64,
    /// YYYYMMDD Geofabrik snapshot date, not a caller-defined semantic version.
    pub version: u32,
    pub hosted: bool,
}
impl Snapshot {
    pub fn validate(&self) -> Result<(), SpelError> {
        let (_, parent, level) = regions::REGIONS
            .iter()
            .find(|(path, _, _)| *path == self.region)
            .ok_or_else(|| bad("Region is outside the closed set"))?;
        if self.parent.as_deref() != *parent
            || self.level != *level
            || self.source_url
                != format!(
                    "https://download.geofabrik.de/{}-latest.osm.pbf",
                    self.region
                )
        {
            return Err(bad("Region hierarchy or canonical source mismatch"));
        }
        if self.cid.is_empty()
            || self.cid.len() > 128
            || !self.cid.bytes().all(|c| c.is_ascii_alphanumeric())
            || self.bytes == 0
            || self.checksum == [0; 16]
            || self.sha256 == [0; 32]
            || !self.hosted
        {
            return Err(bad("Incomplete hosting assertion"));
        }
        let year = self.version / 10000;
        let month = (self.version / 100) % 100;
        let day = self.version % 100;
        let leap =
            year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
        let days = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => 0,
        };
        if !(2000..=9999).contains(&year) || day == 0 || day > days {
            return Err(bad("Invalid snapshot date"));
        }
        Ok(())
    }
}
#[account_type]
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Record {
    pub snapshot: Snapshot,
    pub registrant: [u8; 32],
    pub timestamp: u64,
    pub ordinal: u64,
}
#[account_type]
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Catalog {
    pub schema: u16,
    pub count: u64,
    pub last_timestamp: u64,
}
#[account_type]
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Page {
    pub schema: u16,
    pub number: u64,
    pub records: Vec<Record>,
}
fn bad(message: impl Into<String>) -> SpelError {
    SpelError::custom(1, message)
}
pub fn decode<T: BorshDeserialize>(account: &AccountWithMetadata) -> Result<T, SpelError> {
    borsh::from_slice(account.account.data.as_ref()).map_err(|e| bad(e.to_string()))
}
fn store<T: BorshSerialize>(account: &mut AccountWithMetadata, value: &T) -> Result<(), SpelError> {
    account.account.data = borsh::to_vec(value)
        .map_err(|e| bad(e.to_string()))?
        .try_into()
        .map_err(|_| bad("Account too large"))?;
    Ok(())
}
#[lez_program]
pub mod map_registry {
    #[allow(unused_imports)]
    use super::*;
    #[instruction]
    pub fn initialize(
        #[account(init, pda = literal("maps"))] mut catalog: AccountWithMetadata,
        #[account(signer)] author: AccountWithMetadata,
    ) -> SpelResult {
        store(
            &mut catalog,
            &Catalog {
                schema: SCHEMA,
                count: 0,
                last_timestamp: 0,
            },
        )?;
        Ok(SpelOutput::execute(vec![catalog, author], vec![]))
    }
    #[instruction]
    pub fn create_page(
        #[account(init, pda = [literal("map-page"), arg("number")])] mut page: AccountWithMetadata,
        #[account(signer)] author: AccountWithMetadata,
        number: u64,
    ) -> SpelResult {
        store(
            &mut page,
            &Page {
                schema: SCHEMA,
                number,
                records: vec![],
            },
        )?;
        Ok(SpelOutput::execute(vec![page, author], vec![]))
    }
    /// Single registration is a one-element batch; one atomic transaction stores up to eight.
    #[instruction]
    pub fn register_batch(
        #[account(mut, owner = self_program_id, pda = literal("maps"))]
        mut catalog: AccountWithMetadata,
        #[account(mut, owner = self_program_id, pda = [literal("map-page"), arg("number")])]
        mut page: AccountWithMetadata,
        #[account(signer)] author: AccountWithMetadata,
        number: u64,
        expected_count: u64,
        timestamp: u64,
        snapshots_json: String,
    ) -> SpelResult {
        if snapshots_json.len() > 16384 {
            return Err(bad("Batch exceeds input limit"));
        }
        let snapshots: Vec<Snapshot> =
            serde_json::from_str(&snapshots_json).map_err(|e| bad(e.to_string()))?;
        if snapshots.is_empty() || snapshots.len() > MAX_BATCH {
            return Err(bad("Batch requires 1..8 snapshots"));
        }
        let mut catalog_state: Catalog = decode(&catalog)?;
        let mut page_state: Page = decode(&page)?;
        if catalog_state.schema != SCHEMA
            || page_state.schema != SCHEMA
            || page_state.number != number
            || catalog_state.count != expected_count
            || number != expected_count / PAGE_SIZE as u64
            || page_state.records.len() != (expected_count % PAGE_SIZE as u64) as usize
            || page_state.records.len() + snapshots.len() > PAGE_SIZE
            || timestamp < catalog_state.last_timestamp
        {
            return Err(bad(
                "Stale catalog, invalid timestamp or batch crosses page boundary",
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for snapshot in snapshots {
            snapshot.validate()?;
            if !seen.insert(snapshot.region.clone()) {
                return Err(bad("Duplicate region in batch"));
            }
            if page_state.records.iter().any(|record| {
                record.registrant == *author.account_id.value() && record.snapshot == snapshot
            }) {
                return Err(bad("Duplicate hosting assertion in page"));
            }
            page_state.records.push(Record {
                snapshot,
                registrant: *author.account_id.value(),
                timestamp,
                ordinal: catalog_state.count,
            });
            catalog_state.count = catalog_state
                .count
                .checked_add(1)
                .ok_or_else(|| bad("Registry full"))?;
        }
        catalog_state.last_timestamp = timestamp;
        store(&mut catalog, &catalog_state)?;
        store(&mut page, &page_state)?;
        let end = timestamp
            .checked_add(300001)
            .ok_or_else(|| bad("Timestamp overflow"))?;
        SpelOutput::execute(vec![catalog, page, author], vec![])
            .try_with_timestamp_validity_window(timestamp.saturating_sub(300000)..end)
            .map_err(|e| bad(e.to_string()))
    }
}
