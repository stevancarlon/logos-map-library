// SPDX-License-Identifier: MIT OR Apache-2.0
//! Full SDK file workflows shared by the distribution app and CLI.
//! Imports/uploads and transaction approval are separate explicit steps.
use crate::{Error, Instruction, Reader, Registry, Result, Snapshot};
use lee_core_v03::account::AccountId;
use lee_v03::{fees::FeeDeclaration, public_transaction::Message};
pub use logos_map_distribution::discovery::{SourceVersion, fetch_catalog, latest_version};
pub use logos_map_distribution::transport::StorageNode;
pub use logos_map_distribution::{
    Catalog as RegionCatalog, Region, VerifiedContent, importer, parse_index,
};
use std::path::Path;
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostItem {
    pub region: String,
    pub version: u32,
    pub selected: bool,
    pub input: HostInput,
}
#[derive(Debug, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostInput {
    Local { path: std::path::PathBuf },
    Fetch { destination: std::path::PathBuf },
}
#[derive(Debug, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum HostOutcome {
    Stored { snapshot: Snapshot },
    Failed { region: String, error: String },
}
#[derive(Debug, serde::Serialize)]
pub struct Update {
    pub source: SourceVersion,
    pub registry_version: Option<u32>,
    pub update_available: bool,
    pub verification: &'static str,
}
/// Explicit live discovery; hosted registry queries never invoke this.
#[derive(Debug, serde::Serialize)]
pub struct SourceAvailability {
    pub region: String,
    pub source: Option<SourceVersion>,
    pub error: Option<String>,
}
#[derive(Debug, serde::Serialize)]
pub struct DiscoveredCatalog {
    pub catalog: RegionCatalog,
    pub versions: Vec<SourceAvailability>,
}
pub fn discover_versions() -> Result<DiscoveredCatalog> {
    let catalog = fetch_catalog().map_err(file_error)?;
    let mut versions = vec![];
    // Keep source traffic bounded while avoiding 72 serial network round trips.
    for group in catalog.regions.chunks(4) {
        let rows = std::thread::scope(|scope| {
            let jobs: Vec<_> = group
                .iter()
                .map(|region| {
                    scope.spawn(move || match latest_version(region) {
                        Ok(source) => SourceAvailability {
                            region: region.path.clone(),
                            source: Some(source),
                            error: None,
                        },
                        Err(error) => SourceAvailability {
                            region: region.path.clone(),
                            source: None,
                            error: Some(error.to_string()),
                        },
                    })
                })
                .collect();
            jobs.into_iter()
                .map(|job| {
                    job.join()
                        .map_err(|_| Error::Invalid("source discovery worker failed"))
                })
                .collect::<Result<Vec<_>>>()
        })?;
        versions.extend(rows);
    }
    Ok(DiscoveredCatalog { catalog, versions })
}
/// Exact selected leaves, with opt-outs removed by the caller. Parent extracts
/// are not accepted; the closed set cannot overlap geographically.
pub fn selection(paths: &[String]) -> Result<Vec<Region>> {
    if paths.is_empty() || paths.len() > 72 {
        return Err(Error::Invalid("select between one and 72 regions"));
    }
    let mut seen = std::collections::BTreeSet::new();
    paths
        .iter()
        .map(|path| {
            if !seen.insert(path) {
                return Err(Error::Invalid("duplicate selected region"));
            }
            importer::supported_region(path).map_err(file_error)
        })
        .collect()
}
pub fn compare_updates(sources: Vec<SourceVersion>, records: &[crate::Record]) -> Vec<Update> {
    sources
        .into_iter()
        .map(|source| {
            let registry_version = records
                .iter()
                .filter(|r| r.snapshot.region == source.region)
                .map(|r| r.snapshot.version)
                .max();
            let update_available = registry_version.is_some_and(|v| v < source.version);
            Update {
                source,
                registry_version,
                update_available,
                verification: "unverified_hosting_assertions",
            }
        })
        .collect()
}
/// Partition a selected batch at transaction and page boundaries. Expected counts
/// are explicit and must be checked again at review; never silently resubmit a stale plan.
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub struct Batch {
    pub expected_count: u64,
    pub number: u64,
    pub start: usize,
    pub end: usize,
}
pub fn batches(count: u64, selected: usize) -> Result<Vec<Batch>> {
    if selected == 0 || selected > 72 {
        return Err(Error::Invalid("invalid bulk selection size"));
    }
    count
        .checked_add(selected as u64)
        .ok_or(Error::Invalid("catalog count overflow"))?;
    let mut out = vec![];
    let mut start = 0;
    while start < selected {
        let expected_count = count + start as u64;
        let capacity =
            (crate::PAGE_SIZE as u64 - expected_count % crate::PAGE_SIZE as u64) as usize;
        let end = selected.min(start + capacity.min(logos_maps_v03_core::MAX_BATCH));
        out.push(Batch {
            expected_count,
            number: expected_count / crate::PAGE_SIZE as u64,
            start,
            end,
        });
        start = end;
    }
    Ok(out)
}
pub struct Distribution<R> {
    pub registry: Registry<R>,
    pub storage: StorageNode,
}
fn file_error(error: logos_map_distribution::Error) -> Error {
    Error::Validation(error.to_string())
}
impl<R: Reader> Distribution<R> {
    /// Selected items only; independent failures retain successful public CIDs.
    /// Nothing is signed/registered. `progress` can persist each outcome and return
    /// false to stop before the next item (already stored files remain public).
    pub fn store_bulk(
        &self,
        items: &[HostItem],
        limit: u64,
        scratch: &Path,
        mut progress: impl FnMut(&HostOutcome) -> bool,
    ) -> Result<Vec<HostOutcome>> {
        if items.len() > 72 {
            return Err(Error::Invalid("bulk input exceeds closed set"));
        }
        let selected: Vec<_> = items.iter().filter(|item| item.selected).collect();
        selection(
            &selected
                .iter()
                .map(|item| item.region.clone())
                .collect::<Vec<_>>(),
        )?;
        let mut destinations = std::collections::BTreeSet::new();
        // Validate the entire selection before any download or public upload.
        for item in &selected {
            let region = importer::supported_region(&item.region).map_err(file_error)?;
            importer::dated_source(&region, item.version).map_err(file_error)?;
            if let HostInput::Fetch { destination } = &item.input
                && (!destination.is_absolute() || !destinations.insert(destination))
            {
                return Err(Error::Invalid(
                    "fetch destinations must be absolute and distinct",
                ));
            }
        }
        self.registry.catalog()?;
        let mut outcomes = vec![];
        for item in selected {
            let result = match &item.input {
                HostInput::Local { path } => {
                    self.import_and_store(&item.region, item.version, path, limit, scratch)
                }
                HostInput::Fetch { destination } => {
                    self.fetch_and_store(&item.region, item.version, destination, limit, scratch)
                }
            };
            let outcome = match result {
                Ok(snapshot) => HostOutcome::Stored { snapshot },
                Err(error) => HostOutcome::Failed {
                    region: item.region.clone(),
                    error: error.to_string(),
                },
            };
            let proceed = progress(&outcome);
            outcomes.push(outcome);
            if !proceed {
                break;
            }
        }
        Ok(outcomes)
    }
    /// Source checks require only the registry, never the Storage node.
    pub fn check_updates(&self, paths: &[String], max_pages: u64) -> Result<Vec<Update>> {
        self.registry.check_updates(paths, max_pages)
    }
    /// Checks registry setup before public upload. Returned snapshot is stored, NOT registered.
    pub fn import_and_store(
        &self,
        region: &str,
        version: u32,
        source: &Path,
        limit: u64,
        scratch: &Path,
    ) -> Result<Snapshot> {
        self.registry.catalog()?;
        let region = importer::supported_region(region).map_err(file_error)?;
        logos_map_distribution::hosting::store_local(
            &self.storage,
            &region,
            version,
            source,
            limit,
            scratch,
        )
        .map_err(file_error)
    }
    /// Fetch a dated canonical extract to a new file, verify, then upload verified bytes.
    /// Returns the public CID before any separately approved chain transaction.
    pub fn fetch_and_store(
        &self,
        region: &str,
        version: u32,
        destination: &Path,
        limit: u64,
        scratch: &Path,
    ) -> Result<Snapshot> {
        self.registry.catalog()?;
        let supported = importer::supported_region(region).map_err(file_error)?;
        importer::fetch_dated(&supported, version, destination, limit).map_err(file_error)?;
        self.import_and_store(region, version, destination, limit, scratch)
    }
    /// Prepare one atomic batch against the observed count; explicit page creation is required.
    /// A stale witness fails instead of replacing another host's registration.
    pub fn prepare_registration(
        &self,
        author: AccountId,
        snapshots: &[Snapshot],
        timestamp: u64,
        fee: FeeDeclaration,
    ) -> Result<Message> {
        let catalog = self.registry.catalog()?;
        if snapshots.is_empty()
            || snapshots.len() > logos_maps_v03_core::MAX_BATCH
            || catalog.count % crate::PAGE_SIZE as u64 + snapshots.len() as u64
                > crate::PAGE_SIZE as u64
        {
            return Err(Error::Invalid(
                "batch empty, oversized, or crosses a page; split explicitly",
            ));
        }
        self.registry.prepare(
            author,
            &Instruction::RegisterBatch {
                number: catalog.count / crate::PAGE_SIZE as u64,
                expected_count: catalog.count,
                timestamp,
                snapshots_json: serde_json::to_string(snapshots)
                    .map_err(|_| Error::Invalid("snapshot serialization"))?,
            },
            fee,
        )
    }
    /// Hosted retrieval never contacts Geofabrik. All recorded hashes and byte length must match.
    pub fn download_hosted(
        &self,
        snapshot: &Snapshot,
        limit: u64,
        destination: &Path,
    ) -> Result<VerifiedContent> {
        self.storage
            .download_snapshot(snapshot, limit, destination)
            .map_err(file_error)
    }
    /// Explicit direct-source fallback for a region with no selected hosted snapshot.
    pub fn download_source(
        &self,
        region: &str,
        destination: &Path,
        limit: u64,
    ) -> Result<logos_map_distribution::importer::Imported> {
        let region = importer::supported_region(region).map_err(file_error)?;
        importer::fetch(&region, destination, limit).map_err(file_error)
    }
}

impl<R: Reader> Registry<R> {
    /// Explicit source access for selected paths; registry records are read with a bounded budget.
    pub fn check_updates(&self, paths: &[String], max_pages: u64) -> Result<Vec<Update>> {
        let selected = selection(paths)?;
        let records = self.scan(&crate::Filter::default(), max_pages)?;
        let sources = selected
            .iter()
            .map(|r| latest_version(r).map_err(file_error))
            .collect::<Result<_>>()?;
        Ok(compare_updates(sources, &records))
    }
}
