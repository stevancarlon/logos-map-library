// SPDX-License-Identifier: MIT OR Apache-2.0
//! Canonical import-to-Storage step shared by host CLI and native integrations.
//! Registration remains a separate explicitly approved signing operation.
use crate::{Error, Region, Result, importer, parse_md5_sidecar, transport::StorageNode};
use logos_map_registry::Snapshot;
use std::path::Path;

pub fn store_local(
    storage: &StorageNode,
    region: &Region,
    version: u32,
    input: &Path,
    limit: u64,
    scratch: &Path,
) -> Result<Snapshot> {
    let checksum = importer::dated_checksum(region, version)?;
    let uploaded = storage.upload_verified(input, checksum, limit, scratch)?;
    // Preserve the uploaded CID in errors after this point; it can already be public.
    let after = importer::dated_checksum(region, version).map_err(|error| Error::Invalid(
        format!("Stored CID {} but post-upload source verification failed: {error}; no registration performed", uploaded.cid)
    ))?;
    if after != checksum {
        return Err(Error::Invalid(format!(
            "Stored CID {} but dated source checksum changed; no registration performed",
            uploaded.cid
        )));
    }
    let snapshot = Snapshot {
        region: region.path.clone(),
        parent: region.parent.clone(),
        level: region.level.clone(),
        cid: uploaded.cid,
        source_url: region.source_url.clone(),
        checksum: parse_md5_sidecar(&uploaded.content.md5)?,
        sha256: hex::decode(&uploaded.content.sha256)
            .map_err(|e| Error::Invalid(e.to_string()))?
            .try_into()
            .map_err(|_| Error::Invalid("Invalid SHA-256".into()))?,
        bytes: uploaded.content.bytes,
        version,
        hosted: true,
    };
    snapshot
        .validate()
        .map_err(|e| Error::Invalid(e.to_string()))?;
    Ok(snapshot)
}
