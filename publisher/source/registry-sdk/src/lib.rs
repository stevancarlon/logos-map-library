// SPDX-License-Identifier: MIT OR Apache-2.0
//! Client-side discovery. The sequencer and Storage node are explicitly configured.
use logos_prize_registry::{Catalog, CatalogPage, Entry, PAGE_SIZE, SCHEMA};
use serde::{Deserialize, Serialize};
use spel_framework::prelude::*;
use std::{io::Read, time::Duration};
pub mod publisher;
pub mod terminal;
pub mod verification;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Transport: {0}")]
    Transport(String),
    #[error("Invalid data: {0}")]
    Invalid(String),
}
pub type Result<T> = std::result::Result<T, Error>;

pub trait AccountReader {
    fn account(&self, id: AccountId) -> Result<Account>;
}
pub trait StorageReader {
    fn read(&self, cid: &str, limit: usize) -> Result<Vec<u8>>;
}

pub fn program_bytes(program: &ProgramId) -> [u8; 32] {
    let mut out = [0; 32];
    for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(program) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    out
}
pub fn parse_program(text: &str) -> Result<ProgramId> {
    let bytes = hex::decode(text).map_err(|e| Error::Invalid(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(Error::Invalid("Program ID must contain 32 bytes".into()));
    }
    let mut words = [0; 8];
    for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*chunk);
    }
    Ok(words)
}
pub fn entry_address(registry: &ProgramId, target: &[u8; 32], author: &[u8; 32]) -> AccountId {
    compute_pda(registry, &[&seed_from_str("entry"), target, author])
}

pub struct Registry<R> {
    pub reader: R,
    pub program: ProgramId,
}
impl<R: AccountReader> Registry<R> {
    fn read<T: BorshDeserialize>(&self, id: AccountId) -> Result<T> {
        let account = self.reader.account(id)?;
        if account.program_owner != self.program {
            return Err(Error::Invalid(
                "Account is not owned by this registry".into(),
            ));
        }
        let data: Vec<u8> = account.data.into();
        borsh::from_slice(&data).map_err(|e| Error::Invalid(e.to_string()))
    }
    pub fn lookup(&self, target: &[u8; 32], author: &[u8; 32]) -> Result<Entry> {
        let entry: Entry = self.read(entry_address(&self.program, target, author))?;
        if entry.schema != SCHEMA || &entry.program_id != target || &entry.registrant != author {
            return Err(Error::Invalid("Entry identity mismatch".into()));
        }
        entry
            .metadata
            .validate()
            .map_err(|e| Error::Invalid(e.to_string()))?;
        Ok(entry)
    }
    /// One page at a time. Ordinals are append-only; metadata may change between RPC reads.
    pub fn page(&self, number: u64) -> Result<Vec<Entry>> {
        let catalog: Catalog =
            self.read(compute_pda(&self.program, &[&seed_from_str("registry")]))?;
        if catalog.schema != SCHEMA {
            return Err(Error::Invalid("Unknown catalog schema".into()));
        }
        let start = number
            .checked_mul(PAGE_SIZE as u64)
            .ok_or_else(|| Error::Invalid("Page overflow".into()))?;
        if start >= catalog.count {
            return Ok(vec![]);
        }
        let page: CatalogPage = self.read(compute_pda(
            &self.program,
            &[&seed_from_str("page"), &number.to_seed()],
        ))?;
        let expected = (catalog.count - start).min(PAGE_SIZE as u64) as usize;
        // A concurrent append can lengthen the last page; expose the catalog snapshot prefix.
        if page.schema != SCHEMA
            || page.number != number
            || page.entries.len() < expected
            || page.entries.len() > PAGE_SIZE
        {
            return Err(Error::Invalid("Inconsistent catalog page".into()));
        }
        let mut result = Vec::with_capacity(expected);
        for (index, id) in page.entries.into_iter().take(expected).enumerate() {
            let entry: Entry = self.read(AccountId::new(id))?;
            if entry.schema != SCHEMA
                || entry.ordinal != start + index as u64
                || entry_address(&self.program, &entry.program_id, &entry.registrant)
                    != AccountId::new(id)
            {
                return Err(Error::Invalid("Invalid catalog entry identity".into()));
            }
            entry
                .metadata
                .validate()
                .map_err(|e| Error::Invalid(e.to_string()))?;
            result.push(entry);
        }
        Ok(result)
    }
    pub fn search_page(&self, number: u64, name: &str, author: &str) -> Result<Vec<Entry>> {
        let name = name.to_lowercase();
        let author = author.to_lowercase();
        Ok(self
            .page(number)?
            .into_iter()
            .filter(|entry| {
                entry.metadata.name.to_lowercase().contains(&name)
                    && entry.metadata.author.to_lowercase().contains(&author)
            })
            .collect())
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", content = "detail", rename_all = "snake_case")]
pub enum IdlState {
    Available(serde_json::Value),
    Unavailable(String),
}
#[derive(Debug, Serialize)]
pub struct ResolvedEntry {
    pub entry: Entry,
    pub idl: IdlState,
}
pub fn resolve<S: StorageReader>(entry: Entry, storage: &S) -> ResolvedEntry {
    let idl = match storage
        .read(&entry.metadata.idl_cid, 1024 * 1024)
        .and_then(|bytes| {
            let value: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|e| Error::Invalid(e.to_string()))?;
            let instructions = value
                .get("instructions")
                .and_then(|v| v.as_array())
                .ok_or_else(|| Error::Invalid("IDL lacks instructions array".into()))?;
            if instructions.iter().any(|ix| {
                ix.get("name").and_then(|v| v.as_str()).is_none()
                    || !ix.get("accounts").is_some_and(|v| v.is_array())
                    || !ix.get("args").is_some_and(|v| v.is_array())
            }) {
                return Err(Error::Invalid("Invalid instruction schema".into()));
            }
            Ok(value)
        }) {
        Ok(v) => IdlState::Available(v),
        Err(e) => IdlState::Unavailable(e.to_string()),
    };
    ResolvedEntry { entry, idl }
}

pub struct HttpNode {
    endpoint: String,
    agent: ureq::Agent,
}
impl HttpNode {
    pub fn new(endpoint: &str) -> Result<Self> {
        let url: ureq::http::Uri = endpoint
            .parse()
            .map_err(|_| Error::Invalid("Invalid node URL".into()))?;
        if !matches!(url.scheme_str(), Some("http" | "https"))
            || url.authority().is_none()
            || endpoint.contains('@')
            || endpoint.contains('?')
            || endpoint.contains('#')
        {
            return Err(Error::Invalid(
                "Expected an HTTP(S) node URL without credentials, query, or fragment".into(),
            ));
        }
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .max_redirects(0)
            .build()
            .into();
        Ok(Self {
            endpoint: endpoint.trim_end_matches('/').into(),
            agent,
        })
    }
}
impl AccountReader for HttpNode {
    fn account(&self, id: AccountId) -> Result<Account> {
        serde_json::from_value(self.rpc("getAccount", serde_json::json!([id]))?)
            .map_err(|e| Error::Invalid(e.to_string()))
    }
}
impl StorageReader for HttpNode {
    fn read(&self, cid: &str, limit: usize) -> Result<Vec<u8>> {
        if cid.is_empty() || cid.len() > 128 || !cid.bytes().all(|c| c.is_ascii_alphanumeric()) {
            return Err(Error::Invalid("Invalid storage identifier".into()));
        }
        let mut response = self
            .agent
            .get(format!("{}/data/{cid}/network/stream", self.endpoint))
            .call()
            .map_err(|e| Error::Transport(e.to_string()))?;
        let mut bytes = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| Error::Transport(e.to_string()))?;
        if bytes.len() > limit {
            return Err(Error::Invalid("Storage response exceeds limit".into()));
        }
        Ok(bytes)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImageCheck {
    pub expected_program: String,
    pub computed_program: String,
    pub matches: bool,
}
/// Computes the actual RISC Zero image ID, NOT the SHA-256 of the packaged file.
/// This verifies an artifact against an ID; it does not prove its source provenance.
pub fn verify_image(elf: &[u8], expected: &ProgramId) -> Result<ImageCheck> {
    if elf.len() > 64 * 1024 * 1024 {
        return Err(Error::Invalid("Program binary exceeds 64 MiB".into()));
    }
    let digest = risc0_binfmt::compute_image_id(elf).map_err(|e| Error::Invalid(e.to_string()))?;
    Ok(ImageCheck {
        expected_program: hex::encode(program_bytes(expected)),
        computed_program: hex::encode(digest.as_bytes()),
        matches: digest.as_words() == expected,
    })
}
