// SPDX-License-Identifier: MIT OR Apache-2.0
//! v0.3 map registry discovery and unsigned transaction preparation.
//! This SDK never owns keys, grants approval, or signs transactions.
#[cfg(feature = "distribution")]
pub mod distribution;
pub mod native;
pub mod rpc;
use borsh::BorshDeserialize;
use lee_core_v03::{
    account::{AccountId, ProgramShardSelector, ShardData},
    program::{AccountMeta, PlanInput},
};
use lee_v03::{fees::FeeDeclaration, public_transaction::Message};
pub use logos_map_registry::{Catalog, Instruction, PAGE_SIZE, Page, Record, SCHEMA, Snapshot};
use logos_maps_v03_core::{ENVELOPE_VERSION, Request, spel_program_identity};
use spel_framework::prelude as old;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid map registry data: {0}")]
    Invalid(&'static str),
    #[error("Map registry transport: {0}")]
    Transport(String),
    #[error("Map registry validation: {0}")]
    Validation(String),
}
pub type Result<T> = std::result::Result<T, Error>;

pub trait Reader {
    fn shard(&self, selector: ProgramShardSelector) -> Result<ShardData>;
    fn nonce(&self, account: AccountId) -> Result<u128>;
}
pub fn catalog_address(program: AccountId) -> AccountId {
    AccountId::new(
        *old::compute_pda(
            &spel_program_identity(program),
            &[&old::seed_from_str("maps")],
        )
        .value(),
    )
}
pub fn page_address(program: AccountId, number: u64) -> AccountId {
    use old::ToSeed;
    AccountId::new(
        *old::compute_pda(
            &spel_program_identity(program),
            &[&old::seed_from_str("map-page"), &number.to_seed()],
        )
        .value(),
    )
}
#[derive(Default)]
pub struct Filter<'a> {
    pub region: Option<&'a str>,
    pub parent: Option<&'a str>,
    pub cid: Option<&'a str>,
    pub registrant: Option<&'a [u8; 32]>,
}
impl Filter<'_> {
    fn matches(&self, record: &Record) -> bool {
        self.region.is_none_or(|v| record.snapshot.region == v)
            && self
                .parent
                .is_none_or(|v| record.snapshot.parent.as_deref() == Some(v))
            && self.cid.is_none_or(|v| record.snapshot.cid == v)
            && self.registrant.is_none_or(|v| &record.registrant == v)
    }
}
#[derive(serde::Serialize)]
pub struct QueryPage {
    pub records: Vec<Record>,
    pub next_page: Option<u64>,
    pub catalog_count: u64,
    pub verification: &'static str,
}
pub struct Registry<R> {
    pub reader: R,
    pub program: AccountId,
}
impl<R: Reader> Registry<R> {
    /// Collect a bounded, consistent catalog snapshot. Never return a partial scan as complete.
    pub fn scan(&self, filter: &Filter<'_>, max_pages: u64) -> Result<Vec<Record>> {
        let catalog = self.catalog()?;
        let pages = catalog.count.div_ceil(PAGE_SIZE as u64);
        if max_pages == 0 || max_pages > 4096 || pages > max_pages {
            return Err(Error::Invalid(
                "registry scan exceeds the explicit page budget",
            ));
        }
        let mut records = vec![];
        for number in 0..pages {
            let page = self.query(number, filter)?;
            if page.catalog_count != catalog.count {
                return Err(Error::Invalid("catalog changed during scan; retry read"));
            }
            records.extend(page.records);
        }
        if self.catalog()?.count != catalog.count {
            return Err(Error::Invalid("catalog changed during scan; retry read"));
        }
        records.sort_by_key(|r| std::cmp::Reverse((r.timestamp, r.ordinal)));
        Ok(records)
    }
    fn state(&self, account: AccountId) -> Result<ShardData> {
        self.reader
            .shard(ProgramShardSelector::new(account, self.program))
    }
    fn read<T: BorshDeserialize>(&self, account: AccountId) -> Result<T> {
        borsh::from_slice(&self.state(account)?).map_err(|_| Error::Invalid("malformed state"))
    }
    pub fn catalog(&self) -> Result<Catalog> {
        let catalog: Catalog = self.read(catalog_address(self.program))?;
        if catalog.schema != SCHEMA {
            return Err(Error::Invalid("unsupported schema"));
        }
        Ok(catalog)
    }
    pub fn page_exists(&self, number: u64) -> Result<bool> {
        let state = self.state(page_address(self.program, number))?;
        if state.is_empty() {
            return Ok(false);
        }
        let page: Page = borsh::from_slice(&state).map_err(|_| Error::Invalid("malformed page"))?;
        if page.schema != SCHEMA || page.number != number || page.records.len() > PAGE_SIZE {
            return Err(Error::Invalid("invalid page"));
        }
        Ok(true)
    }
    /// Bounded page query, newest first within the page. Follow next_page explicitly.
    /// A catalog reread rejects changes during the multi-shard read.
    pub fn query(&self, number: u64, filter: &Filter<'_>) -> Result<QueryPage> {
        let catalog = self.catalog()?;
        let start = number
            .checked_mul(PAGE_SIZE as u64)
            .ok_or(Error::Invalid("page overflow"))?;
        let mut result = QueryPage {
            records: vec![],
            next_page: None,
            catalog_count: catalog.count,
            verification: "unverified_hosting_assertions",
        };
        if start >= catalog.count {
            return Ok(result);
        }
        let page: Page = self.read(page_address(self.program, number))?;
        let expected = (catalog.count - start).min(PAGE_SIZE as u64) as usize;
        if page.schema != SCHEMA || page.number != number || page.records.len() != expected {
            return Err(Error::Invalid("inconsistent catalog/page"));
        }
        let mut previous = 0;
        for (i, record) in page.records.into_iter().enumerate() {
            if record.ordinal != start + i as u64
                || record.timestamp < previous
                || record.timestamp > catalog.last_timestamp
            {
                return Err(Error::Invalid("invalid record order"));
            }
            record
                .snapshot
                .validate()
                .map_err(|e| Error::Validation(e.to_string()))?;
            previous = record.timestamp;
            if filter.matches(&record) {
                result.records.push(record);
            }
        }
        if borsh::to_vec(&catalog).unwrap() != borsh::to_vec(&self.catalog()?).unwrap() {
            return Err(Error::Invalid("catalog changed during query; retry read"));
        }
        result.records.reverse();
        result.next_page = (start + (expected as u64) < catalog.count).then_some(number + 1);
        Ok(result)
    }
    /// Return only the next separately approvable step for a bulk selection.
    /// Completion requires matching on-chain records by this author, not a
    /// transport acknowledgement. Nothing is signed, retried or submitted.
    pub fn next_registration(
        &self,
        author: AccountId,
        snapshots: &[Snapshot],
        timestamp: u64,
        max_pages: u64,
    ) -> Result<Option<Instruction>> {
        if snapshots.is_empty() || snapshots.len() > 72 {
            return Err(Error::Invalid("select one to 72 snapshots"));
        }
        let mut regions = std::collections::BTreeSet::new();
        for snapshot in snapshots {
            snapshot
                .validate()
                .map_err(|e| Error::Validation(e.to_string()))?;
            if !regions.insert(&snapshot.region) {
                return Err(Error::Invalid("select only one snapshot per region"));
            }
        }
        if max_pages == 0 || max_pages > 4096 {
            return Err(Error::Invalid("invalid registration scan budget"));
        }
        if self.state(catalog_address(self.program))?.is_empty() {
            return Ok(Some(Instruction::Initialize));
        }
        let catalog = self.catalog()?;
        let author_bytes: [u8; 32] = author.as_ref().try_into().unwrap();
        let records = self.scan(
            &Filter {
                registrant: Some(&author_bytes),
                ..Default::default()
            },
            max_pages,
        )?;
        let pending: Vec<_> = snapshots
            .iter()
            .filter(|snapshot| !records.iter().any(|r| &r.snapshot == *snapshot))
            .cloned()
            .collect();
        let current = self.catalog()?;
        if current.count != catalog.count || current.last_timestamp != catalog.last_timestamp {
            return Err(Error::Invalid(
                "catalog changed during registration planning; retry read",
            ));
        }
        if pending.is_empty() {
            return Ok(None);
        }
        let number = catalog.count / PAGE_SIZE as u64;
        if !self.page_exists(number)? {
            return Ok(Some(Instruction::CreatePage { number }));
        }
        let take = pending
            .len()
            .min(logos_map_registry::MAX_BATCH)
            .min(PAGE_SIZE - (catalog.count % PAGE_SIZE as u64) as usize);
        catalog
            .count
            .checked_add(take as u64)
            .ok_or(Error::Invalid("catalog count overflow"))?;
        Ok(Some(Instruction::RegisterBatch {
            number,
            expected_count: catalog.count,
            timestamp,
            snapshots_json: serde_json::to_string(&pending[..take])
                .map_err(|_| Error::Invalid("snapshot encoding"))?,
        }))
    }
    /// Build an unsigned, state-bound message for the caller's separate review/signing flow.
    /// No automatic page creation, refresh, broadcast, or write retry occurs.
    pub fn prepare(
        &self,
        author: AccountId,
        instruction: &Instruction,
        fee: FeeDeclaration,
    ) -> Result<Message> {
        if fee.payer != author {
            return Err(Error::Invalid("registrant must pay its transaction"));
        }
        let accounts = match instruction {
            Instruction::Initialize => vec![catalog_address(self.program)],
            Instruction::CreatePage { number } => vec![page_address(self.program, *number)],
            Instruction::RegisterBatch { number, .. } => vec![
                catalog_address(self.program),
                page_address(self.program, *number),
            ],
        };
        let request = Request {
            version: ENVELOPE_VERSION,
            instruction_json: serde_json::to_string(instruction)
                .map_err(|_| Error::Invalid("instruction serialization"))?,
            states: accounts
                .iter()
                .map(|id| self.state(*id))
                .collect::<Result<_>>()?,
        };
        let input = PlanInput {
            self_account_id: self.program,
            caller_account_id: None,
            accounts: accounts
                .iter()
                .map(|id| AccountMeta::new(*id, false, self.program))
                .chain([AccountMeta::new(author, true, self.program)])
                .collect(),
            instruction_data: borsh::to_vec(&request)
                .map_err(|_| Error::Invalid("envelope serialization"))?,
        };
        let _validated = logos_maps_v03_core::plan(&input, &request)
            .map_err(|e| Error::Validation(e.to_string()))?;
        Message::try_new_with_fees(
            self.program,
            accounts
                .into_iter()
                .chain([author])
                .map(|id| ProgramShardSelector::new(id, self.program))
                .collect(),
            vec![self.reader.nonce(author)?.into()],
            request,
            fee,
        )
        .map_err(|_| Error::Invalid("message serialization"))
    }
}
