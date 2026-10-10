// SPDX-License-Identifier: MIT OR Apache-2.0
// The checked-in consumer contract must remain the actual SPEL-generated IDL.
#[test]
fn published_idl_matches_spel_generation() {
    let generated: serde_json::Value =
        serde_json::from_str(logos_map_registry::PROGRAM_IDL_JSON).unwrap();
    let published: serde_json::Value =
        serde_json::from_str(include_str!("../map-registry.idl.json")).unwrap();
    assert_eq!(
        published, generated,
        "Regenerate the checked-in map registry IDL"
    );
}
