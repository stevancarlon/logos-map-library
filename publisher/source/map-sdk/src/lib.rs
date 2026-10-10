// SPDX-License-Identifier: MIT OR Apache-2.0
//! Standalone map discovery, independent of the distribution application.
//! Registry assertions are unverified until the consumer applies its trust policy.
pub mod native;
use logos_map_registry::{Catalog, Page, Record, SCHEMA};
pub use logos_map_registry::{PAGE_SIZE, Snapshot};
pub use logos_registry_sdk::{AccountReader, Error, HttpNode, Result};
use serde::Serialize;
use spel_framework::prelude::*;
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
#[derive(Serialize)]
pub struct QueryPage {
    pub records: Vec<Record>,
    pub next_page: Option<u64>,
    pub catalog_count: u64,
    pub verification: &'static str,
}
pub struct MapRegistry<R> {
    pub reader: R,
    pub program: ProgramId,
}
impl<R: AccountReader> MapRegistry<R> {
    fn read<T: BorshDeserialize>(&self, id: AccountId) -> Result<T> {
        let account = self.reader.account(id)?;
        if account.program_owner != self.program {
            return Err(Error::Invalid("Wrong map registry owner".into()));
        }
        borsh::from_slice(account.data.as_ref()).map_err(|e| Error::Invalid(e.to_string()))
    }
    pub fn catalog(&self) -> Result<Catalog> {
        let catalog: Catalog = self.read(compute_pda(&self.program, &[&seed_from_str("maps")]))?;
        if catalog.schema != SCHEMA {
            return Err(Error::Invalid("Unsupported map schema".into()));
        }
        Ok(catalog)
    }
    pub fn page_exists(&self, number: u64) -> Result<bool> {
        let id = compute_pda(
            &self.program,
            &[&seed_from_str("map-page"), &number.to_seed()],
        );
        let account = self.reader.account(id)?;
        if account == Account::default() {
            return Ok(false);
        }
        if account.program_owner != self.program {
            return Err(Error::Invalid("Wrong map page owner".into()));
        }
        let page: Page =
            borsh::from_slice(account.data.as_ref()).map_err(|e| Error::Invalid(e.to_string()))?;
        if page.schema != SCHEMA || page.number != number || page.records.len() > PAGE_SIZE {
            return Err(Error::Invalid("Invalid map registry page".into()));
        }
        Ok(true)
    }
    /// Filters one bounded chain page. Follow next_page to continue; no hidden full scan.
    /// Within each page, newest announcements are returned first.
    pub fn query(&self, number: u64, filter: &Filter<'_>) -> Result<QueryPage> {
        let catalog = self.catalog()?;
        let start = number
            .checked_mul(PAGE_SIZE as u64)
            .ok_or_else(|| Error::Invalid("Page overflow".into()))?;
        if start >= catalog.count {
            return Ok(QueryPage {
                records: vec![],
                next_page: None,
                catalog_count: catalog.count,
                verification: "unverified_hosting_assertions",
            });
        }
        let page: Page = self.read(compute_pda(
            &self.program,
            &[&seed_from_str("map-page"), &number.to_seed()],
        ))?;
        let expected = (catalog.count - start).min(PAGE_SIZE as u64) as usize;
        if page.schema != SCHEMA
            || page.number != number
            || page.records.len() < expected
            || page.records.len() > PAGE_SIZE
        {
            return Err(Error::Invalid("Inconsistent map catalog page".into()));
        }
        let mut records = vec![];
        let mut previous = 0;
        for (i, record) in page.records.into_iter().take(expected).enumerate() {
            if record.ordinal != start + i as u64
                || record.timestamp < previous
                || record.timestamp > catalog.last_timestamp
            {
                return Err(Error::Invalid("Invalid snapshot order".into()));
            }
            record
                .snapshot
                .validate()
                .map_err(|e| Error::Invalid(e.to_string()))?;
            previous = record.timestamp;
            if filter.matches(&record) {
                records.push(record);
            }
        }
        records.reverse();
        Ok(QueryPage {
            records,
            next_page: if start + (expected as u64) < catalog.count {
                Some(number + 1)
            } else {
                None
            },
            catalog_count: catalog.count,
            verification: "unverified_hosting_assertions",
        })
    }
}
/// Every operation is explicit. No automatic initialization, page creation, or retry.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum MapWrite {
    Initialize,
    CreatePage {
        number: u64,
    },
    RegisterBatch {
        expected_count: u64,
        timestamp: u64,
        snapshots: Vec<logos_map_registry::Snapshot>,
    },
}
impl MapRegistry<HttpNode> {
    /// Trusted host operation: may create the needed page, then register one batch.
    /// Never retries an uncertain write or silently refreshes an approved count.
    pub fn register_hosted(
        &self,
        key: &lee::PrivateKey,
        snapshots: Vec<Snapshot>,
        timestamp: u64,
    ) -> Result<Vec<common::HashType>> {
        let catalog = self.catalog()?;
        if snapshots.is_empty()
            || snapshots.len() > logos_map_registry::MAX_BATCH
            || catalog.count % PAGE_SIZE as u64 + snapshots.len() as u64 > PAGE_SIZE as u64
        {
            return Err(Error::Invalid(
                "Host batch is empty, oversized or crosses a registry page".into(),
            ));
        }
        for snapshot in &snapshots {
            snapshot
                .validate()
                .map_err(|e| Error::Invalid(e.to_string()))?;
        }
        let mut transactions = Vec::new();
        let number = catalog.count / PAGE_SIZE as u64;
        let author = AccountId::from(&lee::PublicKey::new_from_private_key(key));
        if catalog.count % PAGE_SIZE as u64 != 0 {
            let existing = self.query(
                number,
                &Filter {
                    registrant: Some(author.value()),
                    ..Default::default()
                },
            )?;
            if existing
                .records
                .iter()
                .any(|record| snapshots.contains(&record.snapshot))
            {
                return Err(Error::Invalid(
                    "This host already registered the identical snapshot on this page".into(),
                ));
            }
        }
        if !self.page_exists(number)? {
            transactions.push(self.submit_included(key, &MapWrite::CreatePage { number })?);
        }
        transactions.push(self.submit_included(
            key,
            &MapWrite::RegisterBatch {
                expected_count: catalog.count,
                timestamp,
                snapshots,
            },
        )?);
        Ok(transactions)
    }
    fn submit_included(&self, key: &lee::PrivateKey, write: &MapWrite) -> Result<common::HashType> {
        let transaction = self.sign(key, write)?;
        let hash = transaction.hash();
        self.reader.submit(&transaction).map_err(|error| {
            Error::Invalid(format!(
                "Submission uncertain for {hash}: {error}. Check this hash before retrying."
            ))
        })?;
        for _ in 0..120 {
            if self.reader.confirmed(hash).map_err(|error| {
                Error::Invalid(format!("Confirmation uncertain for {hash}: {error}"))
            })? {
                return Ok(hash);
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        Err(Error::Invalid(format!(
            "Transaction {hash} still unconfirmed; check status before retrying"
        )))
    }
    /// Trusted caller must approve this operation and own the signing key.
    pub fn sign(
        &self,
        key: &lee::PrivateKey,
        write: &MapWrite,
    ) -> Result<common::transaction::LeeTransaction> {
        use lee::{
            PublicKey, PublicTransaction,
            public_transaction::{Message, WitnessSet},
        };
        use logos_map_registry::Instruction;
        let author = AccountId::from(&PublicKey::new_from_private_key(key));
        let catalog_id = compute_pda(&self.program, &[&seed_from_str("maps")]);
        let (accounts, instruction) = match write {
            MapWrite::Initialize => (vec![catalog_id, author], Instruction::Initialize {}),
            MapWrite::CreatePage { number } => (
                vec![
                    compute_pda(
                        &self.program,
                        &[&seed_from_str("map-page"), &number.to_seed()],
                    ),
                    author,
                ],
                Instruction::CreatePage { number: *number },
            ),
            MapWrite::RegisterBatch {
                expected_count,
                timestamp,
                snapshots,
            } => {
                if snapshots.is_empty()
                    || snapshots.len() > logos_map_registry::MAX_BATCH
                    || (*expected_count % PAGE_SIZE as u64) + snapshots.len() as u64
                        > PAGE_SIZE as u64
                {
                    return Err(Error::Invalid(
                        "Batch is empty, too large, or crosses a page boundary".into(),
                    ));
                }
                for s in snapshots {
                    s.validate().map_err(|e| Error::Invalid(e.to_string()))?;
                }
                let number = *expected_count / PAGE_SIZE as u64;
                (
                    vec![
                        catalog_id,
                        compute_pda(
                            &self.program,
                            &[&seed_from_str("map-page"), &number.to_seed()],
                        ),
                        author,
                    ],
                    Instruction::RegisterBatch {
                        number,
                        expected_count: *expected_count,
                        timestamp: *timestamp,
                        snapshots_json: serde_json::to_string(snapshots)
                            .map_err(|e| Error::Invalid(e.to_string()))?,
                    },
                )
            }
        };
        let author_state = self.reader.account(author)?;
        if author_state.program_owner == [0; 8] {
            return Err(Error::Invalid(
                "Initialize the signing account in the wallet before using the map registry".into(),
            ));
        }
        let message = Message::try_new(
            self.program,
            accounts,
            vec![author_state.nonce],
            instruction,
        )
        .map_err(|e| Error::Invalid(e.to_string()))?;
        let witness = WitnessSet::for_message(&message, &[key]);
        if !witness.is_valid_for(&message) {
            return Err(Error::Invalid("Invalid signature".into()));
        }
        Ok(common::transaction::LeeTransaction::Public(
            PublicTransaction::new(message, witness),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    struct Memory(BTreeMap<AccountId, Account>);
    impl AccountReader for Memory {
        fn account(&self, id: AccountId) -> Result<Account> {
            self.0
                .get(&id)
                .cloned()
                .ok_or(Error::Invalid("Missing fixture".into()))
        }
    }
    fn stored<T: BorshSerialize>(state: T) -> Account {
        Account {
            program_owner: [4; 8],
            data: borsh::to_vec(&state).unwrap().try_into().unwrap(),
            ..Account::default()
        }
    }
    fn registry() -> MapRegistry<Memory> {
        let program = [4; 8];
        let snapshot = logos_map_registry::Snapshot {
            region: "north-america/us/california".into(),
            parent: Some("us".into()),
            level: "subregion".into(),
            cid: "bafyFixture".into(),
            source_url: "https://download.geofabrik.de/north-america/us/california-latest.osm.pbf"
                .into(),
            checksum: [1; 16],
            sha256: [2; 32],
            bytes: 42,
            version: 20261009,
            hosted: true,
        };
        let records = vec![Record {
            snapshot,
            registrant: [3; 32],
            timestamp: 100,
            ordinal: 0,
        }];
        MapRegistry {
            program,
            reader: Memory(BTreeMap::from([
                (
                    compute_pda(&program, &[&seed_from_str("maps")]),
                    stored(Catalog {
                        schema: SCHEMA,
                        count: 1,
                        last_timestamp: 100,
                    }),
                ),
                (
                    compute_pda(&program, &[&seed_from_str("map-page"), &0u64.to_seed()]),
                    stored(Page {
                        schema: SCHEMA,
                        number: 0,
                        records,
                    }),
                ),
            ])),
        }
    }
    #[test]
    fn discovers_by_region_parent_cid_without_central_source() {
        let r = registry();
        for f in [
            Filter {
                region: Some("north-america/us/california"),
                ..Default::default()
            },
            Filter {
                parent: Some("us"),
                ..Default::default()
            },
            Filter {
                cid: Some("bafyFixture"),
                ..Default::default()
            },
        ] {
            let result = r.query(0, &f).unwrap();
            assert_eq!(result.records.len(), 1);
            assert_eq!(result.verification, "unverified_hosting_assertions");
            assert_eq!(result.next_page, None);
        }
        assert!(
            r.query(
                0,
                &Filter {
                    registrant: Some(&[8; 32]),
                    ..Default::default()
                }
            )
            .unwrap()
            .records
            .is_empty()
        );
        assert!(r.query(1, &Filter::default()).unwrap().records.is_empty());
    }
    #[test]
    fn forged_owner_and_inconsistent_catalog_are_rejected() {
        let mut r = registry();
        let catalog = compute_pda(&r.program, &[&seed_from_str("maps")]);
        r.reader.0.get_mut(&catalog).unwrap().program_owner = [9; 8];
        assert!(r.catalog().is_err());
        r.reader.0.insert(
            catalog,
            stored(Catalog {
                schema: SCHEMA,
                count: 2,
                last_timestamp: 100,
            }),
        );
        assert!(r.query(0, &Filter::default()).is_err());
    }
}
