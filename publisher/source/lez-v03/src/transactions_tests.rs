// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::{
    AccountData, AccountView, FeeQuote, NATIVE_PROGRAM,
    token::{self, TokenDefinition, TokenHolding},
    transfer::NativeReader,
};
use logos_wallet_policy::{Grant, Scope};
use std::cell::{Cell, RefCell};
use zeroize::Zeroizing;
struct Peer {
    reads: Cell<usize>,
    sent: Cell<usize>,
    nonce: Cell<u128>,
    tokens: RefCell<BTreeMap<AccountId, Vec<u8>>>,
}
impl Peer {
    fn new() -> Self {
        Self {
            reads: Cell::new(0),
            sent: Cell::new(0),
            nonce: Cell::new(0),
            tokens: RefCell::new(BTreeMap::new()),
        }
    }
}
impl NativeReader for Peer {
    fn native_view(&self, _: AccountId) -> Result<AccountView> {
        self.reads.set(self.reads.get() + 1);
        Ok(AccountView {
            nonce: self.nonce.get(),
            data: AccountData {
                shards: BTreeMap::from([(NATIVE_PROGRAM, 10_000_000u128.to_le_bytes().to_vec())]),
            },
        })
    }
    fn fees(&self) -> Result<FeeQuote> {
        Ok(FeeQuote {
            height: 1,
            base_fee_exec: 8,
            base_fee_stor: 8,
            next_base_fee_exec_floor: 8,
            next_base_fee_exec_ceiling: 9,
            next_base_fee_stor_floor: 8,
            next_base_fee_stor_ceiling: 9,
            max_gas_exec: 10_000_000,
            max_gas_stor: 1_000_000,
        })
    }
}
impl TokenReader for Peer {
    fn token_view(&self, id: AccountId) -> Result<AccountView> {
        Ok(AccountView {
            nonce: self.nonce.get(),
            data: AccountData {
                shards: BTreeMap::from([(
                    token::program(),
                    self.tokens.borrow().get(&id).cloned().unwrap_or_default(),
                )]),
            },
        })
    }
    fn verify_token_program(&self) -> Result<()> {
        Ok(())
    }
}
impl SubmissionNode for Peer {
    fn endpoint(&self) -> &str {
        "http://127.0.0.1:3090"
    }
    fn broadcast(&self, tx: &lee_v03::PublicTransaction) -> Result<[u8; 32]> {
        assert!(tx.witness_set.is_valid_for(&tx.message));
        self.sent.set(self.sent.get() + 1);
        Ok(tx.hash())
    }
    fn observed(&self, _: &lee_v03::PublicTransaction) -> Result<bool> {
        Ok(true)
    }
}
fn app() -> Principal {
    Principal::Module {
        name: "transaction-app".into(),
        instance: String::new(),
    }
}
fn proposal(from: AccountId) -> Proposal {
    Proposal {
        network: "http://127.0.0.1:3090".into(),
        from,
        to: AccountId::from_bytes([7; 32]),
        asset: Asset::Native,
        amount: "100".into(),
        gas_limit: "1000".into(),
        tip: "3".into(),
        max_fee: "20000".into(),
    }
}
fn grant(from: AccountId) -> Grant {
    Grant {
        accounts: [from.bytes()].into(),
        scopes: [Scope::Accounts, Scope::Transactions].into(),
    }
}
#[test]
fn native_requests_require_one_use_consent_and_preserve_durable_outcomes() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("v03.sqlite");
    let mut store = Outbox::create(&path, b"fixture").unwrap();
    let from = store
        .owner_import_public(Zeroizing::new([1; 32]), "sender")
        .unwrap();
    let peer = Peer::new();
    let mut requests = Requests::default();
    assert!(
        requests
            .propose(&mut store, &app(), &peer, proposal(from), 10)
            .is_err()
    );
    assert_eq!(peer.reads.get(), 0);
    store.owner_set_grant(&app(), Some(grant(from))).unwrap();
    let id = requests
        .propose(&mut store, &app(), &peer, proposal(from), 11)
        .unwrap();
    let reviews = requests.reviews(12);
    assert_eq!(reviews[0]["proposal"]["amount"], "100");
    assert_eq!(reviews[0]["proposal"]["max_fee"], "20000");
    assert_eq!(reviews[0]["approval_digest"].as_str().unwrap().len(), 64);
    assert!(
        reviews[0]["fee_notice"]
            .as_str()
            .unwrap()
            .contains("execution fails")
    );
    let other = Principal::Module {
        name: "other-app".into(),
        instance: String::new(),
    };
    assert!(requests.status(&store, &other, &id, 12).is_err());
    let before = std::fs::read(&path).unwrap();
    assert_eq!(
        requests.decide(&mut store, &peer, &id, false, 12).unwrap()["state"],
        "rejected"
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(peer.sent.get(), 0);
    assert!(requests.decide(&mut store, &peer, &id, true, 13).is_err());
    let first = requests
        .propose(&mut store, &app(), &peer, proposal(from), 14)
        .unwrap();
    let second = requests
        .propose(&mut store, &app(), &peer, proposal(from), 14)
        .unwrap();
    let submitted = requests
        .decide(&mut store, &peer, &first, true, 15)
        .unwrap();
    assert_eq!(submitted["execution_outcome"], "unknown");
    assert_eq!(peer.sent.get(), 1);
    assert_eq!(
        requests.status(&store, &app(), &second, 16).unwrap()["state"],
        "cancelled"
    );
    assert!(
        requests
            .decide(&mut store, &peer, &second, true, 16)
            .is_err()
    );
    assert!(
        requests
            .decide(&mut store, &peer, &first, true, 16)
            .is_err()
    );
    drop(store);
    let mut store = Outbox::open(&path, b"fixture").unwrap();
    let mut requests = Requests::default();
    assert_eq!(
        requests.status(&store, &app(), &first, 17).unwrap(),
        submitted
    );
    let stale = requests
        .propose(&mut store, &app(), &peer, proposal(from), 18)
        .unwrap();
    peer.nonce.set(1);
    assert!(
        requests
            .decide(&mut store, &peer, &stale, true, 19)
            .is_err()
    );
    assert_eq!(
        requests.status(&store, &app(), &stale, 20).unwrap()["state"],
        "failed"
    );
    assert!(
        requests
            .decide(&mut store, &peer, &stale, true, 20)
            .is_err()
    );
    assert_eq!(peer.sent.get(), 1);
    let expired = requests
        .propose(&mut store, &app(), &peer, proposal(from), 21)
        .unwrap();
    assert!(
        requests
            .decide(&mut store, &peer, &expired, true, 1000)
            .is_err()
    );
    assert_eq!(peer.sent.get(), 1);
}
#[test]
fn all_reference_token_kinds_use_the_same_owner_consent_and_outbox_path() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("v03.sqlite");
    let mut store = Outbox::create(&path, b"fixture").unwrap();
    let from = store
        .owner_import_public(Zeroizing::new([1; 32]), "sender")
        .unwrap();
    store.owner_set_grant(&app(), Some(grant(from))).unwrap();
    let peer = Peer::new();
    let mut requests = Requests::default();
    let definition = AccountId::from_bytes([5; 32]);
    let up = lee_v03::AccountId::new(definition.bytes());
    let big = 1u128 << 100;
    for (index, (asset, def, holding, amount)) in [
        (
            Asset::Fungible { definition },
            TokenDefinition::Fungible {
                name: "fixture".into(),
                total_supply: big,
                metadata_id: None,
            },
            TokenHolding::Fungible {
                definition_id: up,
                balance: big,
            },
            big,
        ),
        (
            Asset::NftMaster { definition },
            TokenDefinition::NonFungible {
                name: "fixture".into(),
                printable_supply: 7,
                metadata_id: up,
            },
            TokenHolding::NftMaster {
                definition_id: up,
                print_balance: 7,
            },
            7,
        ),
        (
            Asset::NftCopy { definition },
            TokenDefinition::NonFungible {
                name: "fixture".into(),
                printable_supply: 7,
                metadata_id: up,
            },
            TokenHolding::NftPrintedCopy {
                definition_id: up,
                owned: true,
            },
            1,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        *peer.tokens.borrow_mut() = BTreeMap::from([
            (definition, borsh::to_vec(&def).unwrap()),
            (from, borsh::to_vec(&holding).unwrap()),
        ]);
        let mut p = proposal(from);
        p.asset = asset;
        p.amount = amount.to_string();
        let id = requests.propose(&mut store, &app(), &peer, p, 100).unwrap();
        assert_eq!(
            requests.reviews(101)[0]["proposal"]["amount"],
            amount.to_string()
        );
        let sent = requests.decide(&mut store, &peer, &id, true, 101).unwrap();
        assert_eq!(sent["transaction"]["state"], "submitted");
        assert_eq!(peer.sent.get(), index + 1);
        assert!(requests.decide(&mut store, &peer, &id, true, 102).is_err());
    }
    assert_eq!(store.activity_for(&app()).unwrap().len(), 3);
}
#[test]
fn decimal_contract_preserves_u128_and_rejects_lossy_or_ambiguous_inputs() {
    assert_eq!(number::<u128>(&u128::MAX.to_string()).unwrap(), u128::MAX);
    for invalid in [
        "",
        "00",
        "01",
        "-1",
        "+1",
        "1.0",
        " 1",
        "1e3",
        "340282366920938463463374607431768211456",
    ] {
        assert!(number::<u128>(invalid).is_err());
    }
    let mut value = serde_json::to_value(proposal(AccountId::from_bytes([1; 32]))).unwrap();
    value["amount"] = json!(9007199254740993u64);
    assert!(serde_json::from_value::<Proposal>(value).is_err());
}

#[test]
fn wallet_owner_transfer_authorization_is_ephemeral_and_cancellation_does_not_write() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("v03.sqlite");
    let mut store = Outbox::create(&path, b"fixture").unwrap();
    let from = store
        .owner_import_public(Zeroizing::new([1; 32]), "sender")
        .unwrap();
    let owner = Principal::Module {
        name: crate::session::OWNER_MODULE.into(),
        instance: String::new(),
    };
    let peer = Peer::new();
    let mut requests = Requests::default();
    let before = std::fs::read(&path).unwrap();
    store.owner_allow_account(&owner, from).unwrap();
    let id = requests
        .propose(&mut store, &owner, &peer, proposal(from), 10)
        .unwrap();
    requests.decide(&mut store, &peer, &id, false, 11).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(peer.sent.get(), 0);
    assert!(store.grant_for(&owner).unwrap().is_none());
    assert!(
        store.owner_snapshot().unwrap()["grants"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    drop(store);
    let mut store = Outbox::open(&path, b"fixture").unwrap();
    assert!(
        requests
            .propose(&mut store, &owner, &peer, proposal(from), 12)
            .is_err()
    );
}
