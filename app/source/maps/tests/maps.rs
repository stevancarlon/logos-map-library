// SPDX-License-Identifier: MIT OR Apache-2.0
use logos_map_distribution::*;
#[test]
fn known_checksum_and_stream_limits() {
    let expected = parse_md5_sidecar("900150983cd24fb0d6963f7d28e17f72  sample.pbf").unwrap();
    let v = verify_copy(&b"abc"[..], std::io::sink(), expected, 3).unwrap();
    assert_eq!(v.bytes, 3);
    assert_eq!(
        v.sha256,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(matches!(
        verify_copy(&b"abc"[..], std::io::sink(), expected, 2),
        Err(Error::Size)
    ));
    assert!(matches!(
        verify_copy(&b"abd"[..], std::io::sink(), expected, 3),
        Err(Error::Checksum)
    ));
}
#[test]
fn no_overlapping_regions() {
    let leaves = closed_set();
    assert_eq!(leaves.len(), 72);
    for a in &leaves {
        for b in &leaves {
            assert!(!b.starts_with(&format!("{a}/")));
        }
    }
}
#[test]
fn canonical_index_resolution_and_missing_regions() {
    let index=br#"{"features":[{"properties":{"name":"California","urls":{"pbf":"https://download.geofabrik.de/north-america/us/california-latest.osm.pbf"}}}]}"#;
    let c = parse_index(index).unwrap();
    assert_eq!(c.regions.len(), 1);
    assert_eq!(c.regions[0].country, "us");
    assert_eq!(c.missing.len(), 71);
}
#[test]
fn external_source_and_bad_checksum_rejected() {
    let index=br#"{"features":[{"properties":{"name":"Germany","urls":{"pbf":"https://evil.example/europe/germany-latest.osm.pbf"}}}]}"#;
    assert!(parse_index(index).is_err());
    assert!(parse_md5_sidecar("foo").is_err());
}
#[test]
fn retries_are_bounded() {
    assert_eq!(retry_delay(0).unwrap().as_secs(), 1);
    assert_eq!(retry_delay(2).unwrap().as_secs(), 4);
    assert!(retry_delay(3).is_none());
    assert!(retry_delay(u32::MAX).is_none());
}
