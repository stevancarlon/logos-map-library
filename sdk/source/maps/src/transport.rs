// SPDX-License-Identifier: MIT OR Apache-2.0
//! Streaming Storage transport. Hosted downloads have no Geofabrik dependency.
use crate::{
    Error, Region, Result, VerifiedContent, canonical_source, parse_md5_sidecar, verify_copy,
};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
    time::Duration,
};

pub struct StorageNode {
    base: String,
    agent: ureq::Agent,
}
#[derive(Debug, serde::Serialize)]
pub struct Uploaded {
    pub cid: String,
    pub content: VerifiedContent,
    pub registry_status: &'static str,
}
impl StorageNode {
    pub fn new(base: &str) -> Result<Self> {
        let u = url::Url::parse(base).map_err(|e| Error::Invalid(e.to_string()))?;
        if !matches!(u.scheme(), "http" | "https")
            || u.host_str().is_none()
            || !u.username().is_empty()
            || u.password().is_some()
            || u.query().is_some()
            || u.fragment().is_some()
        {
            return Err(Error::Invalid("Invalid Storage API URL".into()));
        }
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(3600)))
            .timeout_connect(Some(Duration::from_secs(15)))
            .max_redirects(0)
            .build()
            .into();
        Ok(Self {
            base: base.trim_end_matches('/').into(),
            agent,
        })
    }
    /// Make a private temporary snapshot, verify it, then upload exactly that snapshot.
    /// The uploaded data is public. No chain registration is implied by upload success.
    pub fn upload_verified(
        &self,
        input: &Path,
        md5: [u8; 16],
        limit: u64,
        scratch: &Path,
    ) -> Result<Uploaded> {
        let mut snapshot = tempfile::tempfile_in(scratch)?;
        let content = verify_copy(File::open(input)?, &mut snapshot, md5, limit)?;
        let mut last_error = String::new();
        let mut cid = None;
        let mut attempts = 0;
        for attempt in 0..4 {
            attempts = attempt + 1;
            snapshot.seek(SeekFrom::Start(0))?;
            let result = self
                .agent
                .post(format!("{}/data?advertise=true", self.base))
                .header("content-type", "application/octet-stream")
                .header("content-length", content.bytes.to_string())
                .send(ureq::SendBody::from_reader(&mut snapshot))
                .and_then(|mut response| {
                    response
                        .body_mut()
                        .with_config()
                        .limit(256)
                        .read_to_string()
                });
            match result {
                Ok(value) => {
                    cid = Some(value.trim().to_owned());
                    break;
                }
                Err(error) => {
                    let transient = matches!(
                        error,
                        ureq::Error::StatusCode(408 | 429 | 500 | 502 | 503 | 504)
                            | ureq::Error::Io(_)
                            | ureq::Error::Timeout(_)
                            | ureq::Error::ConnectionFailed
                    );
                    last_error = error.to_string();
                    if !transient || attempt == 3 {
                        break;
                    }
                    // Rewind the same verified snapshot. Content-addressed upload is
                    // idempotent even when a response was lost after acceptance.
                    std::thread::sleep(Duration::from_secs(1 << attempt));
                }
            }
        }
        let cid = cid.ok_or_else(|| {
            Error::Network(format!(
                "Storage upload failed (attempts: {attempts}): {last_error}"
            ))
        })?;
        validate_cid(&cid)?;
        Ok(Uploaded {
            cid,
            content,
            registry_status: "not_registered",
        })
    }
    /// Writes via a temporary file and refuses to replace an existing destination.
    /// Corrupted/oversized downloads are discarded and never exposed as valid maps.
    pub fn download_verified(
        &self,
        cid: &str,
        md5: [u8; 16],
        limit: u64,
        destination: &Path,
    ) -> Result<VerifiedContent> {
        self.download_checked(cid, md5, limit, destination, None)
    }
    /// Require the complete registry snapshot's SHA-256 and length before publishing.
    /// This verifies matching bytes, not the trustworthiness of the registrant.
    pub fn download_snapshot(
        &self,
        snapshot: &logos_map_registry::Snapshot,
        limit: u64,
        destination: &Path,
    ) -> Result<VerifiedContent> {
        snapshot
            .validate()
            .map_err(|e| Error::Invalid(e.to_string()))?;
        if snapshot.bytes > limit {
            return Err(Error::Size);
        }
        self.download_checked(
            &snapshot.cid,
            snapshot.checksum,
            snapshot.bytes,
            destination,
            Some(snapshot),
        )
    }
    fn download_checked(
        &self,
        cid: &str,
        md5: [u8; 16],
        limit: u64,
        destination: &Path,
        expected: Option<&logos_map_registry::Snapshot>,
    ) -> Result<VerifiedContent> {
        validate_cid(cid)?;
        if destination.try_exists()? {
            return Err(Error::Invalid("Destination already exists".into()));
        }
        let mut response = self
            .agent
            .get(format!("{}/data/{cid}/network/stream", self.base))
            .call()
            .map_err(|e| Error::Network(e.to_string()))?;
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        let content = verify_copy(
            response.body_mut().as_reader(),
            temporary.as_file_mut(),
            md5,
            limit,
        )?;
        if expected.is_some_and(|snapshot| {
            content.bytes != snapshot.bytes || content.sha256 != hex::encode(snapshot.sha256)
        }) {
            return Err(Error::Invalid(
                "Downloaded bytes do not match the registered SHA-256 and length".into(),
            ));
        }
        temporary.as_file().sync_all()?;
        temporary
            .persist_noclobber(destination)
            .map_err(|e| Error::Io(e.error))?;
        Ok(content)
    }
}
fn validate_cid(cid: &str) -> Result<()> {
    if cid.is_empty() || cid.len() > 128 || !cid.bytes().all(|c| c.is_ascii_alphanumeric()) {
        return Err(Error::Invalid("Invalid Storage CID".into()));
    }
    Ok(())
}
/// Sidecar retrieval is isolated to hosting/fallback, not hosted discovery or download.
pub fn geofabrik_checksum(region: &Region) -> Result<[u8; 16]> {
    canonical_source(&region.source_url)?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .max_redirects(0)
        .build()
        .into();
    let mut response = agent
        .get(format!("{}.md5", region.source_url))
        .call()
        .map_err(|e| Error::Network(e.to_string()))?;
    let mut bytes = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(4097)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(Error::Size);
    }
    parse_md5_sidecar(
        std::str::from_utf8(&bytes)
            .map_err(|_| Error::Invalid("Invalid checksum encoding".into()))?,
    )
}
