// SPDX-License-Identifier: MIT OR Apache-2.0
//! Explicit canonical-source import. Discovery and hosted downloads never call this.
use crate::{
    Error, Region, Result, VerifiedContent, canonical_source, parse_md5_sidecar, verify_copy,
};
use std::{io::Read, path::Path, time::Duration};

#[derive(Debug, serde::Serialize)]
pub struct Imported {
    pub region: String,
    pub source_url: String,
    pub content: VerifiedContent,
    pub registry_status: &'static str,
}

/// Pinned, checked catalog also displayed by the native UI. No network lookup.
pub fn supported_region(path: &str) -> Result<Region> {
    #[derive(serde::Deserialize)]
    struct Catalog {
        canonical_regions: Vec<Region>,
    }
    let catalog: Catalog = serde_json::from_str(include_str!("../data/catalog.json"))
        .map_err(|e| Error::Invalid(e.to_string()))?;
    catalog
        .canonical_regions
        .into_iter()
        .find(|r| r.path == path)
        .ok_or_else(|| Error::Invalid("Unknown canonical region path".into()))
}

/// Streams to a sibling temporary file; publishes only if both sidecar reads
/// agree and the bytes match. No upload or chain write occurs. A latest snapshot
/// changing during import is an error, never a claim about a particular date.
pub fn fetch(region: &Region, destination: &Path, limit: u64) -> Result<Imported> {
    let url = canonical_source(&region.source_url)?;
    let path = url
        .path()
        .trim_start_matches('/')
        .trim_end_matches("-latest.osm.pbf");
    if path != region.path
        || !crate::closed_set()
            .iter()
            .any(|leaf| path == leaf || path.ends_with(&format!("/{leaf}")))
    {
        return Err(Error::Invalid(
            "Source and supported region do not match".into(),
        ));
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(3600)))
        .timeout_connect(Some(Duration::from_secs(15)))
        .max_redirects(0)
        .build()
        .into();
    let content = fetch_from(&agent, &region.source_url, destination, limit, |attempt| {
        std::thread::sleep(Duration::from_secs(1 << attempt));
    })?;
    Ok(Imported {
        region: region.path.clone(),
        source_url: region.source_url.clone(),
        content,
        registry_status: "not_uploaded_or_registered",
    })
}

/// Exact dated source. A caller-supplied version never becomes verified merely
/// because it is well formed: hosting must fetch this dated snapshot's sidecar.
pub fn dated_source(region: &Region, version: u32) -> Result<String> {
    let canonical = supported_region(&region.path)?;
    if *region != canonical {
        return Err(Error::Invalid(
            "Region differs from canonical catalog".into(),
        ));
    }
    let year = version / 10000;
    let month = version / 100 % 100;
    let day = version % 100;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if !(2000..=2099).contains(&year) || day == 0 || day > days {
        return Err(Error::Invalid(
            "Expected a valid Geofabrik date YYYYMMDD in 2000–2099".into(),
        ));
    }
    Ok(region.source_url.replace(
        "-latest.osm.pbf",
        &format!("-{:06}.osm.pbf", version % 1000000),
    ))
}
pub fn dated_checksum(region: &Region, version: u32) -> Result<[u8; 16]> {
    let source = dated_source(region, version)?;
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .max_redirects(0)
        .build()
        .into();
    checksum(&agent, &source)
}
pub fn fetch_dated(
    region: &Region,
    version: u32,
    destination: &Path,
    limit: u64,
) -> Result<Imported> {
    let source = dated_source(region, version)?;
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(3600)))
        .timeout_connect(Some(Duration::from_secs(15)))
        .max_redirects(0)
        .build()
        .into();
    let content = fetch_from(&agent, &source, destination, limit, |attempt| {
        std::thread::sleep(Duration::from_secs(1 << attempt));
    })?;
    Ok(Imported {
        region: region.path.clone(),
        source_url: source,
        content,
        registry_status: "not_uploaded_or_registered",
    })
}

fn checksum(agent: &ureq::Agent, source: &str) -> Result<[u8; 16]> {
    let mut response = get(agent, &format!("{source}.md5"))?;
    let mut bytes = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::Network(e.to_string()))?;
    if bytes.len() > 4096 {
        return Err(Error::Size);
    }
    parse_md5_sidecar(
        std::str::from_utf8(&bytes)
            .map_err(|_| Error::Invalid("Invalid checksum encoding".into()))?,
    )
}

pub(crate) fn redirect_target(source: &str, location: &str) -> Result<String> {
    let original = url::Url::parse(source).map_err(|e| Error::Invalid(e.to_string()))?;
    canonical_source(source.trim_end_matches(".md5"))?;
    let target = original
        .join(location)
        .map_err(|e| Error::Invalid(e.to_string()))?;
    let suffix = if source.ends_with(".md5") {
        ".osm.pbf.md5"
    } else {
        ".osm.pbf"
    };
    let prefix = original
        .path()
        .split_once("-latest")
        .ok_or_else(|| Error::Invalid("Invalid redirect source".into()))?
        .0;
    let date = target
        .path()
        .strip_prefix(&format!("{prefix}-"))
        .and_then(|v| v.strip_suffix(suffix));
    if target.origin() != original.origin()
        || !target.username().is_empty()
        || target.password().is_some()
        || target.query().is_some()
        || target.fragment().is_some()
        || !date.is_some_and(|d| d.len() == 6 && d.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(Error::Invalid(
            "Geofabrik redirect did not identify a dated snapshot of the same region".into(),
        ));
    }
    Ok(target.to_string())
}

fn get(agent: &ureq::Agent, source: &str) -> Result<ureq::http::Response<ureq::Body>> {
    let response = agent
        .get(source)
        .config()
        .max_redirects(0)
        .build()
        .call()
        .map_err(network)?;
    if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Error::Invalid("Redirect lacks a valid location".into()))?;
        let target = redirect_target(source, location)?;
        let response = agent
            .get(target)
            .config()
            .max_redirects(0)
            .build()
            .call()
            .map_err(network)?;
        if response.status().as_u16() != 200 {
            return Err(Error::Invalid(
                "Expected a complete dated snapshot response".into(),
            ));
        }
        Ok(response)
    } else if response.status().as_u16() == 200 {
        Ok(response)
    } else {
        Err(Error::Invalid("Expected a complete source response".into()))
    }
}

fn network(error: ureq::Error) -> Error {
    if matches!(
        error,
        ureq::Error::StatusCode(408 | 429 | 500 | 502 | 503 | 504)
            | ureq::Error::Io(_)
            | ureq::Error::Timeout(_)
            | ureq::Error::ConnectionFailed
    ) {
        Error::Network(error.to_string())
    } else {
        Error::Invalid(format!("Source request failed: {error}"))
    }
}

struct NetworkReader<R> {
    inner: R,
    failed: bool,
}
impl<R: Read> Read for NetworkReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let result = self.inner.read(buffer);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

fn fetch_from(
    agent: &ureq::Agent,
    source: &str,
    destination: &Path,
    limit: u64,
    mut backoff: impl FnMut(u32),
) -> Result<VerifiedContent> {
    if limit == 0 {
        return Err(Error::Size);
    }
    if destination.try_exists()? {
        return Err(Error::Invalid("Destination already exists".into()));
    }
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    for attempt in 0..4 {
        let result = (|| {
            let expected = checksum(agent, source)?;
            let mut response = get(agent, source)?;
            if response
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .is_some_and(|length| length > limit)
            {
                return Err(Error::Size);
            }
            let mut file = tempfile::NamedTempFile::new_in(parent)?;
            let mut reader = NetworkReader {
                inner: response.body_mut().as_reader(),
                failed: false,
            };
            let content =
                verify_copy(&mut reader, file.as_file_mut(), expected, limit).map_err(|e| {
                    if reader.failed {
                        Error::Network(e.to_string())
                    } else {
                        e
                    }
                })?;
            if content.bytes == 0 {
                return Err(Error::Invalid("Empty map extract".into()));
            }
            if checksum(agent, source)? != expected {
                return Err(Error::Invalid(
                    "Geofabrik snapshot changed during import; retry with the current snapshot"
                        .into(),
                ));
            }
            file.as_file().sync_all()?;
            file.persist_noclobber(destination)
                .map_err(|e| Error::Io(e.error))?;
            Ok(content)
        })();
        match result {
            Err(Error::Network(_)) if attempt < 3 => backoff(attempt),
            other => return other,
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, net::TcpListener, thread};
    const MD5: &str = "900150983cd24fb0d6963f7d28e17f72  map.osm.pbf";
    #[test]
    fn dated_sources_bind_calendar_and_exact_canonical_region() {
        let mut region = supported_region("africa/ethiopia").unwrap();
        assert_eq!(
            dated_source(&region, 20240229).unwrap(),
            "https://download.geofabrik.de/africa/ethiopia-240229.osm.pbf"
        );
        for date in [20230229, 20261301, 20260001, 20260100, 19991231, 21000101] {
            assert!(dated_source(&region, date).is_err());
        }
        region.source_url = "https://download.geofabrik.de/africa/kenya-latest.osm.pbf".into();
        assert!(dated_source(&region, 20261008).is_err());
    }
    #[test]
    fn redirect_is_restricted_to_same_regions_dated_https_snapshot() {
        let source = "https://download.geofabrik.de/africa/ethiopia-latest.osm.pbf";
        assert_eq!(
            redirect_target(source, "ethiopia-261008.osm.pbf").unwrap(),
            "https://download.geofabrik.de/africa/ethiopia-261008.osm.pbf"
        );
        for location in [
            "https://evil.invalid/africa/ethiopia-261008.osm.pbf",
            "http://download.geofabrik.de/africa/ethiopia-261008.osm.pbf",
            "kenya-261008.osm.pbf",
            "ethiopia-latest.osm.pbf",
            "ethiopia-261008.osm.pbf?token=a",
            "https://user@download.geofabrik.de/africa/ethiopia-261008.osm.pbf",
        ] {
            assert!(redirect_target(source, location).is_err(), "{location}");
        }
    }
    #[test]
    fn canonical_catalog_selection_and_source_binding() {
        let mut region = supported_region("europe/germany").unwrap();
        assert!(supported_region("germany").is_err());
        region.source_url = "https://download.geofabrik.de/europe/france-latest.osm.pbf".into();
        let dir = tempfile::tempdir().unwrap();
        assert!(fetch(&region, &dir.path().join("map.pbf"), 100).is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
    fn source(replies: Vec<(u16, &'static str)>) -> (String, thread::JoinHandle<Vec<String>>) {
        source_lengths(
            replies
                .into_iter()
                .map(|(code, body)| (code, body, body.len()))
                .collect(),
        )
    }
    fn source_lengths(
        replies: Vec<(u16, &'static str, usize)>,
    ) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/map.osm.pbf", listener.local_addr().unwrap());
        let task = thread::spawn(move || {
            let mut paths = vec![];
            for (code, body, length) in replies {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    socket.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                    assert!(request.len() < 8192);
                }
                paths.push(
                    String::from_utf8(request)
                        .unwrap()
                        .lines()
                        .next()
                        .unwrap()
                        .to_owned(),
                );
                write!(socket, "HTTP/1.1 {code} Response\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{body}").unwrap();
            }
            paths
        });
        (url, task)
    }
    #[test]
    fn interrupted_body_restarts_instead_of_appending_partial_bytes() {
        let (url, task) = source_lengths(vec![
            (200, MD5, MD5.len()),
            (200, "a", 3),
            (200, MD5, MD5.len()),
            (200, "abc", 3),
            (200, MD5, MD5.len()),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("map.pbf");
        let mut retries = 0;
        fetch_from(&ureq::agent(), &url, &path, 3, |_| retries += 1).unwrap();
        assert_eq!(retries, 1);
        assert_eq!(std::fs::read(path).unwrap(), b"abc");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        task.join().unwrap();
    }
    #[test]
    fn retries_transient_failure_and_publishes_only_verified_snapshot() {
        let (url, task) = source(vec![(503, "busy"), (200, MD5), (200, "abc"), (200, MD5)]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("map.pbf");
        let mut delays = vec![];
        let result = fetch_from(&ureq::agent(), &url, &path, 3, |n| delays.push(n)).unwrap();
        assert_eq!(delays, vec![0]);
        assert_eq!(result.bytes, 3);
        assert_eq!(std::fs::read(&path).unwrap(), b"abc");
        assert_eq!(task.join().unwrap().len(), 4);
        assert!(fetch_from(&ureq::agent(), &url, &path, 3, |_| panic!()).is_err());
    }
    #[test]
    fn changed_sidecar_corruption_and_size_never_publish() {
        for replies in [
            vec![
                (200, MD5),
                (200, "abc"),
                (200, "d41d8cd98f00b204e9800998ecf8427e"),
            ],
            vec![(200, MD5), (200, "bad")],
            vec![(200, MD5), (200, "too big")],
        ] {
            let (url, task) = source(replies);
            let dir = tempfile::tempdir().unwrap();
            assert!(
                fetch_from(
                    &ureq::agent(),
                    &url,
                    &dir.path().join("map.pbf"),
                    3,
                    |_| panic!()
                )
                .is_err()
            );
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
            task.join().unwrap();
        }
    }
}
