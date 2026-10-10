// SPDX-License-Identifier: MIT OR Apache-2.0
//! Explicit live canonical discovery probe; no writes or hosting claims.
#[cfg(feature = "distribution")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use logos_maps_v03_sdk::distribution::{fetch_catalog, importer, latest_version};
    let catalog = fetch_catalog()?;
    let source = latest_version(&importer::supported_region("africa/ethiopia")?)?;
    assert_eq!(catalog.regions.len(), 72);
    assert!(catalog.missing.is_empty());
    println!(
        "{}",
        serde_json::json!({"result":"passed","catalog":catalog,"source_version":source,
        "scope":"Live Geofabrik discovery; no registry writes or hosting claim"})
    );
    Ok(())
}
#[cfg(not(feature = "distribution"))]
fn main() {
    panic!("Enable the distribution feature")
}
