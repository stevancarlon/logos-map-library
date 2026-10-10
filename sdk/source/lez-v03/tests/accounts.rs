// SPDX-License-Identifier: MIT OR Apache-2.0
use lee_v03::PublicTransaction;
use logos_lez_v03::{
    AccountData, AccountId, AccountView, FeeQuote, NATIVE_PROGRAM, Result,
    outbox::{Outbox, State, SubmissionNode},
    transfer::{NativeReader, NativeTransfer, Wallet},
};
use logos_wallet_policy::{Grant, Scope, principal::Principal};
use std::{cell::Cell, collections::BTreeMap, rc::Rc};
use zeroize::Zeroizing;
const PASSWORD: &[u8] = b"account store fixture password";
const REQUEST: &str = "12345678901234567890123456789012";
#[derive(Clone, Default)]
struct Peer {
    reads: Rc<Cell<usize>>,
    sent: Rc<Cell<usize>>,
}
impl NativeReader for Peer {
    fn native_view(&self, _: AccountId) -> Result<AccountView> {
        self.reads.set(self.reads.get() + 1);
        Ok(AccountView {
            nonce: 0,
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
impl SubmissionNode for Peer {
    fn endpoint(&self) -> &str {
        "http://127.0.0.1:3090"
    }
    fn broadcast(&self, tx: &PublicTransaction) -> Result<[u8; 32]> {
        assert!(tx.witness_set.is_valid_for(&tx.message));
        self.sent.set(self.sent.get() + 1);
        Ok(tx.hash())
    }
    fn observed(&self, _: &PublicTransaction) -> Result<bool> {
        Ok(true)
    }
}
fn grant(account: AccountId) -> Grant {
    Grant {
        accounts: [account.bytes()].into(),
        scopes: [Scope::Accounts, Scope::Transactions].into(),
    }
}
fn transfer(from: AccountId) -> NativeTransfer {
    NativeTransfer {
        from,
        to: AccountId::from_bytes([7; 32]),
        amount: 100,
        gas_limit: 1000,
        tip: 3,
        max_fee: 20_000,
    }
}
fn app() -> Principal {
    Principal::Module {
        name: "fixture.accounts".into(),
        instance: String::new(),
    }
}

#[test]
fn keys_labels_selection_and_grants_survive_rotation_without_plaintext_or_overwrite() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("wallet.sqlite");
    let mut store = Outbox::create(&path, PASSWORD).unwrap();
    let first = store
        .owner_import_public(Zeroizing::new([1; 32]), "PRIVATE FIXTURE LABEL")
        .unwrap();
    assert!(
        store
            .owner_import_public(Zeroizing::new([1; 32]), "duplicate")
            .is_err()
    );
    assert!(
        store
            .owner_import_public(Zeroizing::new([0; 32]), "invalid")
            .is_err()
    );
    let second = store.owner_create_public("second").unwrap();
    store.owner_select(second).unwrap();
    store.owner_rename(first, "PRIVATE RENAMED LABEL").unwrap();
    assert!(store.owner_rename(first, "bad\nlabel").is_err());
    store.owner_set_grant(&app(), Some(grant(first))).unwrap();
    assert!(
        store
            .owner_rotate_password(b"wrong", b"replacement password")
            .is_err()
    );
    store
        .owner_rotate_password(PASSWORD, b"replacement password")
        .unwrap();
    drop(store);
    assert!(Outbox::open(&path, PASSWORD).is_err());
    let reopened = Outbox::open(&path, b"replacement password").unwrap();
    let infos = reopened.owner_accounts().unwrap();
    assert_eq!(infos.len(), 2);
    assert!(infos[1].selected);
    assert_eq!(infos[0].account, first);
    assert_eq!(reopened.accounts_for(&app()).unwrap(), vec![first]);
    assert!(Outbox::create(&path, PASSWORD).is_err());
    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes.windows(7).any(|b| b == b"PRIVATE"));
}
#[test]
fn stored_key_requires_one_use_approval_and_outbox_survives_restart() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("wallet.sqlite");
    let mut store = Outbox::create(&path, PASSWORD).unwrap();
    let from = store
        .owner_import_public(Zeroizing::new([1; 32]), "sender")
        .unwrap();
    let peer = Peer::default();
    let wallet = Wallet::new(peer.clone(), peer.endpoint()).unwrap();
    assert!(
        store
            .prepare_native(&app(), &wallet, transfer(from), 100)
            .is_err()
    );
    assert_eq!(peer.reads.get(), 0);
    store.owner_set_grant(&app(), Some(grant(from))).unwrap();
    let prepared = store
        .prepare_native(&app(), &wallet, transfer(from), 100)
        .unwrap();
    assert!(
        store
            .execute_native(&app(), REQUEST, &wallet, &peer, &prepared, 101)
            .is_err()
    );
    store.owner_rename(from, "renamed sender").unwrap();
    assert!(store.owner_decide(prepared.prompt().id, true, 101).is_err());
    let replacement = store
        .prepare_native(&app(), &wallet, transfer(from), 101)
        .unwrap();
    assert!(replacement.prompt().id > prepared.prompt().id);
    let prepared = replacement;
    store.owner_decide(prepared.prompt().id, true, 101).unwrap();
    let status = store
        .execute_native(&app(), REQUEST, &wallet, &peer, &prepared, 102)
        .unwrap();
    assert_eq!(status.state, State::Submitted);
    assert_eq!(store.activity_for(&app()).unwrap(), vec![status.clone()]);
    assert!(store.activity_for(&Principal::LocalCli).unwrap().is_empty());
    assert!(
        store
            .execute_native(&app(), REQUEST, &wallet, &peer, &prepared, 103)
            .is_err()
    );
    assert_eq!(peer.sent.get(), 1);
    drop(store);
    let mut reopened = Outbox::open(&path, PASSWORD).unwrap();
    assert_eq!(reopened.status(&app(), REQUEST).unwrap(), status);
    assert_eq!(reopened.owner_accounts().unwrap()[0].account, from);
    assert_eq!(
        reopened
            .reconcile(&app(), REQUEST, &peer, 104)
            .unwrap()
            .state,
        State::IncludedBySequencer
    );
    assert_eq!(peer.sent.get(), 1);
}

#[test]
fn terminal_authorization_and_cancel_never_persist_a_grant_or_outbox_record() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("wallet.sqlite");
    let mut store = Outbox::create(&path, PASSWORD).unwrap();
    let from = store
        .owner_import_public(Zeroizing::new([1; 32]), "sender")
        .unwrap();
    let before = std::fs::read(&path).unwrap();
    let peer = Peer::default();
    let wallet = Wallet::new(peer.clone(), peer.endpoint()).unwrap();
    store.owner_allow_local_cli_account(from).unwrap();
    let prepared = store
        .prepare_native(&Principal::LocalCli, &wallet, transfer(from), 100)
        .unwrap();
    store
        .owner_decide(prepared.prompt().id, false, 101)
        .unwrap();
    assert!(
        store
            .execute_native(
                &Principal::LocalCli,
                REQUEST,
                &wallet,
                &peer,
                &prepared,
                102
            )
            .is_err()
    );
    assert!(store.activity_for(&Principal::LocalCli).unwrap().is_empty());
    assert_eq!(peer.sent.get(), 0);
    drop(store);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let mut reopened = Outbox::open(&path, PASSWORD).unwrap();
    assert!(
        reopened
            .prepare_native(&Principal::LocalCli, &wallet, transfer(from), 103)
            .is_err()
    );
}
#[test]
fn restart_revocation_and_other_sessions_invalidate_approved_work() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("wallet.sqlite");
    let mut store = Outbox::create(&path, PASSWORD).unwrap();
    let from = store
        .owner_import_public(Zeroizing::new([1; 32]), "sender")
        .unwrap();
    store.owner_set_grant(&app(), Some(grant(from))).unwrap();
    let peer = Peer::default();
    let wallet = Wallet::new(peer.clone(), peer.endpoint()).unwrap();
    let prepared = store
        .prepare_native(&app(), &wallet, transfer(from), 100)
        .unwrap();
    store.owner_decide(prepared.prompt().id, true, 101).unwrap();
    let mut reopened = Outbox::open(&path, PASSWORD).unwrap();
    assert!(
        reopened
            .execute_native(&app(), REQUEST, &wallet, &peer, &prepared, 102)
            .is_err()
    );
    reopened.owner_set_grant(&app(), None).unwrap();
    assert!(store.accounts_for(&app()).is_err());
    assert!(
        store
            .execute_native(&app(), REQUEST, &wallet, &peer, &prepared, 103)
            .is_err()
    );
    assert!(store.owner_rename(from, "stale overwrite").is_err());
    assert!(reopened.accounts_for(&app()).is_err());
    assert_eq!(peer.sent.get(), 0);
}
#[test]
fn proof_only_permission_cannot_disclose_accounts_or_sign() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("wallet.sqlite");
    let mut store = Outbox::create(&path, PASSWORD).unwrap();
    let from = store
        .owner_import_public(Zeroizing::new([1; 32]), "sender")
        .unwrap();
    store
        .owner_set_grant(
            &app(),
            Some(Grant {
                accounts: Default::default(),
                scopes: [Scope::CollectionProof].into(),
            }),
        )
        .unwrap();
    assert!(store.accounts_for(&app()).is_err());
    let peer = Peer::default();
    let wallet = Wallet::new(peer.clone(), peer.endpoint()).unwrap();
    assert!(
        store
            .prepare_native(&app(), &wallet, transfer(from), 100)
            .is_err()
    );
    assert_eq!(peer.reads.get(), 0);
    assert!(
        store
            .owner_set_grant(&app(), Some(grant(AccountId::from_bytes([9; 32]))))
            .is_err()
    );
    // A legacy payload has the same outer encrypted SQLite container, but no
    // accepted v0.3 format. Opening it must not import keys or change its payload.
    let old = temp.path().join("legacy.sqlite");
    let payload = br#"{"schema":1,"accounts":[]}"#;
    let old_store = logos_wallet_store::Store::create(&old, PASSWORD, payload).unwrap();
    assert!(Outbox::open(&old, PASSWORD).is_err());
    assert_eq!(&*old_store.load(PASSWORD).unwrap().payload, payload);
}
