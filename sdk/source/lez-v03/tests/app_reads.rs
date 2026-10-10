// SPDX-License-Identifier: MIT OR Apache-2.0
use logos_lez_v03::{
    AccountData, AccountId, AccountView, Error, FeeQuote, NATIVE_PROGRAM, Result,
    outbox::Outbox,
    token::{self, TokenDefinition, TokenHolding, TokenReader},
    transfer::NativeReader,
};
use logos_wallet_policy::{Grant, Scope, principal::Principal};
use std::{cell::Cell, collections::BTreeMap};
use zeroize::Zeroizing;
struct Peer {
    reads: Cell<usize>,
    kind: Cell<u8>,
}
fn definition() -> AccountId {
    AccountId::from_bytes([91; 32])
}
fn up() -> lee_v03::AccountId {
    lee_v03::AccountId::new(definition().bytes())
}
impl NativeReader for Peer {
    fn native_view(&self, _: AccountId) -> Result<AccountView> {
        self.reads.set(self.reads.get() + 1);
        Ok(AccountView {
            nonce: 0,
            data: AccountData {
                shards: BTreeMap::from([(NATIVE_PROGRAM, u128::MAX.to_le_bytes().to_vec())]),
            },
        })
    }
    fn fees(&self) -> Result<FeeQuote> {
        Err(Error::Invalid("Read must not request a fee quote"))
    }
}
impl TokenReader for Peer {
    fn token_view(&self, id: AccountId) -> Result<AccountView> {
        self.reads.set(self.reads.get() + 1);
        let data = if id == definition() {
            borsh::to_vec(&if self.kind.get() == 0 {
                TokenDefinition::Fungible {
                    name: "fixture token".into(),
                    total_supply: u128::MAX,
                    metadata_id: None,
                }
            } else {
                TokenDefinition::NonFungible {
                    name: "fixture collection".into(),
                    printable_supply: 8,
                    metadata_id: up(),
                }
            })
            .unwrap()
        } else {
            borsh::to_vec(&match self.kind.get() {
                0 => TokenHolding::Fungible {
                    definition_id: up(),
                    balance: u128::MAX,
                },
                1 | 2 => TokenHolding::NftPrintedCopy {
                    definition_id: up(),
                    owned: self.kind.get() == 1,
                },
                _ => TokenHolding::NftMaster {
                    definition_id: up(),
                    print_balance: if self.kind.get() == 3 { 6 } else { 0 },
                },
            })
            .unwrap()
        };
        Ok(AccountView {
            nonce: 0,
            data: AccountData {
                shards: BTreeMap::from([(token::program(), data)]),
            },
        })
    }
    fn verify_token_program(&self) -> Result<()> {
        self.reads.set(self.reads.get() + 1);
        Ok(())
    }
}
fn app(name: &str) -> Principal {
    Principal::Module {
        name: name.into(),
        instance: String::new(),
    }
}
fn grant(id: AccountId, scope: Scope) -> Grant {
    Grant {
        accounts: [id.bytes()].into(),
        scopes: [scope].into(),
    }
}
#[test]
fn public_read_permissions_precede_rpc_and_do_not_imply_other_disclosures() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("wallet.sqlite");
    let password = b"public-read synthetic password";
    let mut store = Outbox::create(&path, password).unwrap();
    let id = store
        .owner_import_public(Zeroizing::new([1; 32]), "secret account label")
        .unwrap();
    let other = store
        .owner_import_public(Zeroizing::new([2; 32]), "other private label")
        .unwrap();
    let peer = Peer {
        reads: Cell::new(0),
        kind: Cell::new(0),
    };
    let caller = app("reader");
    assert!(store.native_balance_for(&caller, &peer, id).is_err());
    assert_eq!(peer.reads.get(), 0);
    store
        .owner_set_grant(&caller, Some(grant(id, Scope::PublicBalance)))
        .unwrap();
    assert!(store.nft_holdings_for(&caller, &peer, id).is_err());
    assert!(store.native_balance_for(&caller, &peer, other).is_err());
    assert!(store.native_balance_for(&app("other"), &peer, id).is_err());
    assert!(store.accounts_for(&caller).is_err());
    assert_eq!(peer.reads.get(), 0);
    let native = store.native_balance_for(&caller, &peer, id).unwrap();
    assert_eq!(native["native_balance"], u128::MAX.to_string());
    assert!(!native.to_string().contains("label"));
    let fungible = store.fungible_balance_for(&caller, &peer, id).unwrap();
    assert_eq!(fungible["token"]["balance"], u128::MAX.to_string());
    assert!(fungible.get("native_balance").is_none());
    peer.kind.set(1);
    let hidden = store.fungible_balance_for(&caller, &peer, id).unwrap();
    assert!(hidden["token"].is_null());
    assert!(!hidden.to_string().contains("fixture collection"));
    store
        .owner_set_grant(&caller, Some(grant(id, Scope::NftEnumeration)))
        .unwrap();
    let reads = peer.reads.get();
    assert!(store.native_balance_for(&caller, &peer, id).is_err());
    assert!(store.fungible_balance_for(&caller, &peer, id).is_err());
    assert!(store.accounts_for(&caller).is_err());
    assert_eq!(peer.reads.get(), reads);
    let nft = store.nft_holdings_for(&caller, &peer, id).unwrap();
    assert_eq!(nft["collections"][0]["count"], "1");
    assert!(nft.get("native_balance").is_none());
    assert!(nft.get("nonce").is_none());
    assert!(!nft.to_string().contains("secret account label"));
    assert_eq!(
        store
            .collection_membership_for(&caller, &peer, id, definition())
            .unwrap()["member"],
        true
    );
    assert_eq!(
        store
            .collection_membership_for(&caller, &peer, id, other)
            .unwrap()["member"],
        false
    );
    let stale = Outbox::open(&path, password).unwrap();
    store
        .owner_set_grant(&caller, Some(grant(id, Scope::CollectionProof)))
        .unwrap();
    let reads = peer.reads.get();
    assert!(stale.nft_holdings_for(&caller, &peer, id).is_err());
    assert!(store.nft_holdings_for(&caller, &peer, id).is_err());
    assert!(store.native_balance_for(&caller, &peer, id).is_err());
    assert_eq!(peer.reads.get(), reads);
}
#[test]
fn nft_enumeration_counts_owned_assets_not_print_rights_and_excludes_fungibles() {
    let temp = tempfile::tempdir().unwrap();
    let mut store =
        Outbox::create(&temp.path().join("wallet.sqlite"), b"NFT fixture password").unwrap();
    let id = store
        .owner_import_public(Zeroizing::new([3; 32]), "hidden label")
        .unwrap();
    let caller = app("nft_reader");
    store
        .owner_set_grant(&caller, Some(grant(id, Scope::NftEnumeration)))
        .unwrap();
    let peer = Peer {
        reads: Cell::new(0),
        kind: Cell::new(1),
    };
    for (kind, count) in [(0, 0), (1, 1), (2, 0), (3, 1), (4, 0)] {
        peer.kind.set(kind);
        let value = store.nft_holdings_for(&caller, &peer, id).unwrap();
        let items = value["collections"].as_array().unwrap();
        assert_eq!(items.len(), count);
        if count == 1 {
            assert_eq!(items[0]["count"], "1");
            assert_eq!(items[0]["collection"]["metadata_status"], "not_fetched");
            assert_eq!(items[0]["holdings"][0]["holding_account"], id.to_string());
            assert!(
                items[0]["holdings"][0]["identifier_note"]
                    .as_str()
                    .unwrap()
                    .contains("not a stable")
            );
        }
        if kind == 3 {
            assert_eq!(
                items[0]["holdings"][0]["asset"]["remaining_print_rights"],
                "5"
            );
        }
    }
}
