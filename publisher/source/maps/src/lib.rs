// SPDX-License-Identifier: MIT OR Apache-2.0
//! Region selection and bounded streaming verification for LP-0018.
pub mod discovery;
pub mod hosting;
pub mod importer;
pub mod transport;
use md5::Md5;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
};

pub const COUNTRIES: &[&str] = &[
    "germany",
    "france",
    "great-britain",
    "italy",
    "spain",
    "poland",
    "netherlands",
    "belgium",
    "switzerland",
    "austria",
    "czech-republic",
    "sweden",
    "norway",
    "denmark",
    "finland",
    "portugal",
    "greece",
    "ireland-and-northern-ireland",
    "hungary",
    "romania",
    "bulgaria",
    "ukraine",
    "belarus",
    "turkey",
    "canada",
    "mexico",
    "japan",
    "south-korea",
    "indonesia",
    "thailand",
    "vietnam",
    "malaysia-singapore-brunei",
    "philippines",
    "pakistan",
    "bangladesh",
    "iran",
    "australia",
    "brazil",
    "argentina",
    "colombia",
    "peru",
    "chile",
    "south-africa",
    "egypt",
    "nigeria",
    "kenya",
    "morocco",
    "ethiopia",
];
pub const SUBREGIONS: &[(&str, &[&str])] = &[
    (
        "us",
        &[
            "california",
            "texas",
            "florida",
            "new-york",
            "washington",
            "illinois",
            "georgia",
            "pennsylvania",
        ],
    ),
    (
        "india",
        &[
            "central-zone",
            "eastern-zone",
            "north-eastern-zone",
            "northern-zone",
            "southern-zone",
            "western-zone",
        ],
    ),
    (
        "china",
        &[
            "guangdong",
            "jiangsu",
            "shandong",
            "zhejiang",
            "sichuan",
            "henan",
        ],
    ),
    (
        "russia",
        &[
            "central-fed-district",
            "northwestern-fed-district",
            "volga-fed-district",
            "siberian-fed-district",
        ],
    ),
];
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid region or catalog: {0}")]
    Invalid(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("Checksum mismatch; content has not been verified")]
    Checksum,
    #[error("Content exceeds configured size limit")]
    Size,
    #[error("Network: {0}")]
    Network(String),
}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Region {
    pub path: String,
    pub name: String,
    pub country: String,
    pub parent: Option<String>,
    pub level: String,
    pub source_url: String,
}
pub fn closed_set() -> Vec<String> {
    let mut list: Vec<String> = COUNTRIES.iter().map(|s| (*s).into()).collect();
    for (country, leaves) in SUBREGIONS {
        list.extend(leaves.iter().map(|s| format!("{country}/{s}")));
    }
    list
}
fn canonical_source(text: &str) -> Result<url::Url> {
    let url = url::Url::parse(text).map_err(|e| Error::Invalid(e.to_string()))?;
    if url.scheme() != "https"
        || url.host_str() != Some("download.geofabrik.de")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().ends_with("-latest.osm.pbf")
    {
        return Err(Error::Invalid("Not a canonical Geofabrik PBF URL".into()));
    }
    Ok(url)
}
#[derive(Debug, Serialize)]
pub struct Catalog {
    pub regions: Vec<Region>,
    pub missing: Vec<String>,
    pub index_sha256: String,
}
pub fn parse_index(bytes: &[u8]) -> Result<Catalog> {
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(Error::Size);
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| Error::Invalid(e.to_string()))?;
    let features = value
        .get("features")
        .and_then(|v| v.as_array())
        .ok_or_else(|| Error::Invalid("Missing features".into()))?;
    let wanted = closed_set();
    let mut found = BTreeMap::new();
    for feature in features {
        let Some(props) = feature.get("properties") else {
            continue;
        };
        let Some(source) = props.pointer("/urls/pbf").and_then(|v| v.as_str()) else {
            continue;
        };
        let url = canonical_source(source)?;
        let extract = url
            .path()
            .trim_start_matches('/')
            .trim_end_matches("-latest.osm.pbf");
        for leaf in &wanted {
            if extract == leaf || extract.ends_with(&format!("/{leaf}")) {
                let parts: Vec<_> = leaf.split('/').collect();
                let (country, parent, level) = if parts.len() == 2 {
                    (parts[0].to_owned(), Some(parts[0].to_owned()), "subregion")
                } else {
                    (leaf.clone(), None, "country")
                };
                let name = props
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| Error::Invalid("Missing region name".into()))?;
                let region = Region {
                    path: extract.to_owned(),
                    name: name.to_owned(),
                    country,
                    parent,
                    level: level.into(),
                    source_url: source.into(),
                };
                if found.insert(leaf.clone(), region).is_some() {
                    return Err(Error::Invalid(format!("Duplicate region {leaf}")));
                }
            }
        }
    }
    let missing = wanted
        .into_iter()
        .filter(|s| !found.contains_key(s))
        .collect();
    Ok(Catalog {
        regions: found.into_values().collect(),
        missing,
        index_sha256: hex::encode(Sha256::digest(bytes)),
    })
}
/// MD5 is required solely for matching Geofabrik's published snapshot checksum.
/// SHA-256 is recorded too; MD5 alone is not a cryptographic authenticity guarantee.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerifiedContent {
    pub bytes: u64,
    pub md5: String,
    pub sha256: String,
}
pub fn parse_md5_sidecar(text: &str) -> Result<[u8; 16]> {
    let raw = text
        .split_whitespace()
        .next()
        .ok_or_else(|| Error::Invalid("Empty checksum".into()))?;
    let bytes = hex::decode(raw).map_err(|_| Error::Invalid("Invalid MD5 checksum".into()))?;
    bytes
        .try_into()
        .map_err(|_| Error::Invalid("MD5 must contain 16 bytes".into()))
}
/// Destination should be a fresh temporary file, exposed only after success.
/// No unverified bytes should be uploaded or advertised to peers.
pub fn verify_copy(
    mut input: impl Read,
    mut output: impl Write,
    expected: [u8; 16],
    limit: u64,
) -> Result<VerifiedContent> {
    let mut md5 = Md5::new();
    let mut sha = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count = count.checked_add(n as u64).ok_or(Error::Size)?;
        if count > limit {
            return Err(Error::Size);
        }
        md5.update(&buffer[..n]);
        sha.update(&buffer[..n]);
        output.write_all(&buffer[..n])?;
    }
    let actual: [u8; 16] = md5.finalize().into();
    if actual != expected {
        return Err(Error::Checksum);
    }
    output.flush()?;
    Ok(VerifiedContent {
        bytes: count,
        md5: hex::encode(actual),
        sha256: hex::encode(sha.finalize()),
    })
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostedVersion {
    pub region: Region,
    pub content: VerifiedContent,
    pub cid: String,
    pub source_version: String,
    pub timestamp: u64,
}
/// An SDK caller supplies records from its verified registry adapter. This function
/// does not assert that arbitrary input records have been registered on-chain.
pub fn latest<'a>(records: &'a [HostedVersion], path: &str) -> Option<&'a HostedVersion> {
    records
        .iter()
        .filter(|r| r.region.path == path)
        .max_by_key(|r| r.timestamp)
}
pub fn coverage(records: &[HostedVersion]) -> (usize, usize) {
    let allowed = closed_set();
    let mut countries = BTreeSet::new();
    let mut leaves = BTreeSet::new();
    for r in records {
        if !r.cid.is_empty()
            && allowed
                .iter()
                .any(|leaf| r.region.path == *leaf || r.region.path.ends_with(&format!("/{leaf}")))
        {
            countries.insert(&r.region.country);
            leaves.insert(&r.region.path);
        }
    }
    (countries.len(), leaves.len())
}
/// Three retries after the first attempt, capped at four seconds. The caller
/// retries only transient transport failures, not invalid data/checksums.
pub fn retry_delay(attempt: u32) -> Option<std::time::Duration> {
    match attempt {
        0..=2 => Some(std::time::Duration::from_secs(1u64 << attempt)),
        _ => None,
    }
}
