// SPDX-License-Identifier: MIT OR Apache-2.0
use logos_lez_v03::{outbox::Outbox, shielded::PrivateIdentity};
use zeroize::Zeroizing;
#[test]
fn private_keys_share_encrypted_revision_and_rotation_without_becoming_public_accounts() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("v03.sqlite");
    let password = b"private vault synthetic password";
    let mut store = Outbox::create(&path, password).unwrap();
    let public = store
        .owner_import_public(Zeroizing::new([1; 32]), "public label")
        .unwrap();
    let id = store
        .owner_import_private(
            PrivateIdentity::from_seed(Zeroizing::new([17; 32]), [18; 32]),
            "PRIVATE SECRET LABEL",
        )
        .unwrap();
    assert!(
        store
            .owner_import_private(
                PrivateIdentity::from_seed(Zeroizing::new([17; 32]), [18; 32]),
                "duplicate"
            )
            .is_err()
    );
    assert!(store.owner_create_private("").is_err());
    assert_eq!(store.owner_accounts().unwrap().len(), 1);
    assert_eq!(store.owner_accounts().unwrap()[0].account, public);
    let details = store.owner_private_accounts().unwrap();
    assert_eq!(details[0]["account"], id.to_string());
    assert_eq!(details[0]["initialized"], false);
    assert!(details[0]["native_balance"].is_null());
    assert!(details[0].get("seed").is_none());
    let stale = Outbox::open(&path, password).unwrap();
    store
        .owner_rotate_password(password, b"private rotated password")
        .unwrap();
    assert!(stale.owner_private_accounts().is_err());
    drop(store);
    assert!(Outbox::open(&path, password).is_err());
    let recovered = Outbox::open(&path, b"private rotated password").unwrap();
    assert_eq!(recovered.owner_private_accounts().unwrap(), details);
    assert_eq!(recovered.owner_accounts().unwrap().len(), 1);
    let bytes = std::fs::read(path).unwrap();
    assert!(!bytes.windows(20).any(|b| b == b"PRIVATE SECRET LABEL"));
}
