// SPDX-License-Identifier: MIT OR Apache-2.0
use logos_prize_registry::{Catalog, CatalogPage, Entry, Metadata, SCHEMA, registry::*};
use spel_framework::prelude::*;

const PROGRAM: [u32; 8] = [9; 8];
const TARGET: [u8; 32] = [3; 32];

fn author() -> AccountWithMetadata {
    account(AccountId::new([7; 32]), true)
}
fn account(id: AccountId, signed: bool) -> AccountWithMetadata {
    AccountWithMetadata {
        account_id: id,
        account: Account::default(),
        is_authorized: signed,
    }
}
fn stored<T: BorshSerialize>(id: AccountId, value: T) -> AccountWithMetadata {
    let mut a = account(id, false);
    a.account.program_owner = PROGRAM;
    a.account.data = borsh::to_vec(&value).unwrap().try_into().unwrap();
    a
}
fn metadata() -> Metadata {
    Metadata {
        name: "Example token".into(),
        version: "1.0.0".into(),
        author: "Test fixture".into(),
        description: "Synthetic program used only for tests".into(),
        tags: vec!["token".into()],
        idl_cid: "bafyTestIdl".into(),
        source_cid: "bafyTestSource".into(),
        source_commit: "a".repeat(40),
        build_config_cid: "bafyTestBuild".into(),
    }
}
fn inputs() -> Vec<AccountWithMetadata> {
    vec![
        stored(
            compute_pda(&PROGRAM, &[&seed_from_str("registry")]),
            Catalog {
                schema: SCHEMA,
                count: 0,
            },
        ),
        stored(
            compute_pda(&PROGRAM, &[&seed_from_str("page"), &0u64.to_seed()]),
            CatalogPage {
                schema: SCHEMA,
                number: 0,
                entries: vec![],
            },
        ),
        account(
            compute_pda(
                &PROGRAM,
                &[
                    &seed_from_str("entry"),
                    &TARGET,
                    author().account_id.value(),
                ],
            ),
            false,
        ),
        author(),
    ]
}
fn register_fixture(inputs: Vec<AccountWithMetadata>, deployer: bool) -> SpelResult {
    let [catalog, page, entry, author]: [_; 4] = inputs.try_into().unwrap();
    register(
        catalog,
        page,
        entry,
        author,
        TARGET,
        0,
        100,
        serde_json::to_string(&metadata()).unwrap(),
        deployer,
    )
}
fn entry_from(output: &SpelOutput) -> Entry {
    let bytes: Vec<u8> = output.post_states[2].account().data.clone().into();
    borsh::from_slice(&bytes).unwrap()
}

#[test]
fn registers_and_indexes_author_scoped_entry() {
    let a = inputs();
    __validate_register(&a, &PROGRAM, &vec![], &0, &TARGET).unwrap();
    let output = register_fixture(a, false).unwrap();
    assert_eq!(output.timestamp_validity_window.start(), Some(0));
    assert_eq!(output.timestamp_validity_window.end(), Some(300_101));
    let entry = entry_from(&output);
    assert_eq!(entry.registrant, *author().account_id.value());
    assert_eq!(entry.ordinal, 0);
    let bytes: Vec<u8> = output.post_states[1].account().data.clone().into();
    let page: CatalogPage = borsh::from_slice(&bytes).unwrap();
    assert_eq!(page.entries.len(), 1);
}

#[test]
fn spoofed_deployer_claim_is_rejected() {
    assert!(register_fixture(inputs(), true).is_err());
}

#[test]
fn framework_rejects_unsigned_or_forged_accounts() {
    let mut a = inputs();
    a[3].is_authorized = false;
    assert!(__validate_register(&a, &PROGRAM, &vec![], &0, &TARGET).is_err());
    let mut a = inputs();
    a[2].account_id = AccountId::new([66; 32]);
    assert!(__validate_register(&a, &PROGRAM, &vec![], &0, &TARGET).is_err());
    let mut a = inputs();
    a[0].account.program_owner = [5; 8];
    assert!(__validate_register(&a, &PROGRAM, &vec![], &0, &TARGET).is_err());
}

#[test]
fn duplicate_entry_is_rejected_by_init_validation() {
    let mut a = inputs();
    a[2].account = register_fixture(inputs(), false).unwrap().post_states[2]
        .account()
        .clone();
    assert!(__validate_register(&a, &PROGRAM, &vec![], &0, &TARGET).is_err());
}

#[test]
fn updates_require_original_author_and_revision() {
    let output = register_fixture(inputs(), false).unwrap();
    let mut entry = inputs()[2].clone();
    entry.account = output.post_states[2].account().clone();
    entry.account.program_owner = PROGRAM;
    let payload = serde_json::to_string(&metadata()).unwrap();
    let mut impostor = author();
    impostor.account_id = AccountId::new([8; 32]);
    assert!(update(entry.clone(), impostor, TARGET, 0, payload.clone()).is_err());
    assert!(update(entry.clone(), author(), TARGET, 1, payload.clone()).is_err());
    __validate_update(&[entry.clone(), author()], &PROGRAM, &vec![], &TARGET).unwrap();
    let updated = update(entry, author(), TARGET, 0, payload).unwrap();
    let bytes: Vec<u8> = updated.post_states[0].account().data.clone().into();
    let state: Entry = borsh::from_slice(&bytes).unwrap();
    assert_eq!(state.revision, 1);
    assert_eq!(state.submitted_at, 100);
}

#[test]
fn malformed_metadata_is_rejected() {
    let mut m = metadata();
    m.source_cid = "https://example.org/source".into();
    assert!(m.validate().is_err());
    let mut m = metadata();
    m.description = "x".repeat(2049);
    assert!(m.validate().is_err());
    let mut m = metadata();
    m.source_commit = "abc".into();
    assert!(m.validate().is_err());
}

#[test]
fn inconsistent_page_cannot_corrupt_catalog() {
    let mut a = inputs();
    a[1] = stored(
        a[1].account_id,
        CatalogPage {
            schema: SCHEMA,
            number: 0,
            entries: vec![[8; 32]],
        },
    );
    assert!(register_fixture(a, false).is_err());
}
