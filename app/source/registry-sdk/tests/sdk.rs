// SPDX-License-Identifier: MIT OR Apache-2.0
use logos_prize_registry::{Catalog, CatalogPage, Entry, Metadata, SCHEMA};
use logos_registry_sdk::*;
use spel_framework::prelude::*;
use std::collections::BTreeMap;
const PROGRAM: ProgramId = [7; 8];
fn fixture() -> Entry {
    Entry {
        schema: SCHEMA,
        program_id: [3; 32],
        registrant: [8; 32],
        ordinal: 0,
        revision: 0,
        submitted_at: 12,
        metadata: Metadata {
            name: "Token".into(),
            version: "1".into(),
            author: "Example author".into(),
            description: "Test fixture".into(),
            tags: vec![],
            idl_cid: "bafyTest".into(),
            source_cid: "bafySource".into(),
            source_commit: "a".repeat(40),
            build_config_cid: "bafyBuild".into(),
        },
    }
}
struct Memory(BTreeMap<[u8; 32], Account>);
impl AccountReader for Memory {
    fn account(&self, id: AccountId) -> Result<Account> {
        self.0
            .get(id.value())
            .cloned()
            .ok_or(Error::Transport("Missing fixture".into()))
    }
}
fn stored<T: BorshSerialize>(v: T) -> Account {
    Account {
        program_owner: PROGRAM,
        data: borsh::to_vec(&v).unwrap().try_into().unwrap(),
        ..Account::default()
    }
}
fn setup() -> Registry<Memory> {
    let entry = fixture();
    let address = entry_address(&PROGRAM, &entry.program_id, &entry.registrant);
    Registry {
        program: PROGRAM,
        reader: Memory(BTreeMap::from([
            (*address.value(), stored(entry)),
            (
                *compute_pda(&PROGRAM, &[&seed_from_str("registry")]).value(),
                stored(Catalog {
                    schema: SCHEMA,
                    count: 1,
                }),
            ),
            (
                *compute_pda(&PROGRAM, &[&seed_from_str("page"), &0u64.to_seed()]).value(),
                stored(CatalogPage {
                    schema: SCHEMA,
                    number: 0,
                    entries: vec![*address.value()],
                }),
            ),
        ])),
    }
}
struct BrokenStorage;
impl StorageReader for BrokenStorage {
    fn read(&self, _: &str, _: usize) -> Result<Vec<u8>> {
        Err(Error::Transport("Unavailable".into()))
    }
}
struct InvalidIdl;
impl StorageReader for InvalidIdl {
    fn read(&self, _: &str, _: usize) -> Result<Vec<u8>> {
        Ok(br#"{"hello":"world"}"#.to_vec())
    }
}
#[test]
fn unavailable_idl_preserves_metadata() {
    let r = resolve(fixture(), &BrokenStorage);
    assert_eq!(r.entry.metadata.name, "Token");
    assert!(matches!(r.idl, IdlState::Unavailable(_)));
}
#[test]
fn malformed_idl_preserves_metadata() {
    assert!(matches!(
        resolve(fixture(), &InvalidIdl).idl,
        IdlState::Unavailable(_)
    ));
}
#[test]
fn lookup_enumeration_search_and_bounds() {
    let r = setup();
    assert_eq!(r.lookup(&[3; 32], &[8; 32]).unwrap(), fixture());
    assert_eq!(r.page(0).unwrap().len(), 1);
    assert!(r.page(1).unwrap().is_empty());
    assert!(r.page(u64::MAX).is_err());
    assert_eq!(r.search_page(0, "tok", "EXAMPLE").unwrap().len(), 1);
    assert!(r.search_page(0, "other", "").unwrap().is_empty());
}
#[test]
fn spoofed_account_owner_rejected() {
    let mut r = setup();
    let id = entry_address(&PROGRAM, &[3; 32], &[8; 32]);
    r.reader.0.get_mut(id.value()).unwrap().program_owner = [0; 8];
    assert!(r.lookup(&[3; 32], &[8; 32]).is_err());
}
#[test]
fn parse_is_little_endian_and_roundtrips() {
    let p = [0x01020304; 8];
    assert_eq!(program_bytes(&p)[..4], [4, 3, 2, 1]);
    assert_eq!(parse_program(&hex::encode(program_bytes(&p))).unwrap(), p);
    assert!(parse_program("1234").is_err());
}
#[test]
fn invalid_elf_is_not_verified() {
    assert!(verify_image(b"not an ELF", &PROGRAM).is_err());
}
#[test]
fn node_urls_reject_credentials_and_query() {
    assert!(HttpNode::new("https://user:password@example.com").is_err());
    assert!(HttpNode::new("file:///etc/passwd").is_err());
    assert!(HttpNode::new("https://example.com?token=foo").is_err());
}
