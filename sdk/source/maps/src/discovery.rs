// SPDX-License-Identifier: MIT OR Apache-2.0
//! Explicit canonical-source discovery. Hosted reads never call these functions.
use crate::{Catalog, Error, Region, Result, importer, parse_index};
use std::{io::Read, time::Duration};
pub const INDEX_URL: &str = "https://download.geofabrik.de/index-v1-nogeom.json";
fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .max_redirects(0)
        .build()
        .into()
}
pub fn fetch_catalog() -> Result<Catalog> {
    let mut response = agent()
        .get(INDEX_URL)
        .call()
        .map_err(|e| Error::Network(e.to_string()))?;
    if response.status().as_u16() != 200 {
        return Err(Error::Invalid("Expected canonical index response".into()));
    }
    let mut bytes = vec![];
    response
        .body_mut()
        .as_reader()
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    parse_index(&bytes)
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct SourceVersion {
    pub region: String,
    pub version: u32,
    pub dated_url: String,
}
/// Resolve the actual dated snapshot named by Geofabrik. Never infer a version
/// from wall-clock time, index download time, or an HTTP Last-Modified header.
pub fn latest_version(region: &Region) -> Result<SourceVersion> {
    if *region != importer::supported_region(&region.path)? {
        return Err(Error::Invalid("Noncanonical region".into()));
    }
    let response = agent()
        .head(&region.source_url)
        .call()
        .map_err(|e| Error::Network(e.to_string()))?;
    if !matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
        return Err(Error::Invalid(
            "Source did not identify a dated version; cannot compare updates".into(),
        ));
    }
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Error::Invalid("Source version redirect lacks Location".into()))?;
    resolve_version(region, location)
}
fn resolve_version(region: &Region, location: &str) -> Result<SourceVersion> {
    let dated_url = importer::redirect_target(&region.source_url, location)?;
    let suffix = dated_url
        .strip_suffix(".osm.pbf")
        .and_then(|v| v.rsplit_once('-'))
        .map(|(_, v)| v)
        .ok_or_else(|| Error::Invalid("Missing dated source suffix".into()))?;
    let version = 20_000_000
        + suffix
            .parse::<u32>()
            .map_err(|_| Error::Invalid("Invalid source date".into()))?;
    if importer::dated_source(region, version)? != dated_url {
        return Err(Error::Invalid("Source date mismatch".into()));
    }
    Ok(SourceVersion {
        region: region.path.clone(),
        version,
        dated_url,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_requires_same_region_canonical_dated_redirect_and_real_date() {
        let region = importer::supported_region("africa/ethiopia").unwrap();
        assert_eq!(
            resolve_version(&region, "ethiopia-261009.osm.pbf")
                .unwrap()
                .version,
            20261009
        );
        for bad in [
            "https://example.org/ethiopia-261009.osm.pbf",
            "/africa/kenya-261009.osm.pbf",
            "ethiopia-260230.osm.pbf",
            "ethiopia-latest.osm.pbf",
            "ethiopia-261009.osm.pbf?x=1",
            "//evil.example/africa/ethiopia-261009.osm.pbf",
        ] {
            assert!(resolve_version(&region, bad).is_err(), "{bad}");
        }
    }
}
