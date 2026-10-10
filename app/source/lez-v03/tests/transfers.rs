// SPDX-License-Identifier: MIT OR Apache-2.0
use lee_v03::{PrivateKey, PublicKey, V03State};
use logos_lez_v03::{
    AccountData, AccountId, AccountView, FeeQuote, NATIVE_PROGRAM, Result,
    transfer::{NativeReader, NativeTransfer, Wallet},
};
use logos_wallet_policy::{AppId, Effect, Grant, Policy, Request, Scope};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::Rc,
};

#[derive(Clone)]
struct Memory {
    views: Rc<RefCell<BTreeMap<AccountId, AccountView>>>,
    quote: Rc<RefCell<FeeQuote>>,
    reads: Rc<Cell<usize>>,
}
impl NativeReader for Memory {
    fn native_view(&self, account: AccountId) -> Result<AccountView> {
        self.reads.set(self.reads.get() + 1);
        Ok(self.views.borrow()[&account].clone())
    }
    fn fees(&self) -> Result<FeeQuote> {
        self.reads.set(self.reads.get() + 1);
        Ok(self.quote.borrow().clone())
    }
}
fn id(key: &PrivateKey) -> AccountId {
    AccountId::from_bytes(*lee_v03::AccountId::from(&PublicKey::new_from_private_key(key)).value())
}
fn view(balance: u128) -> AccountView {
    AccountView {
        nonce: 0,
        data: AccountData {
            shards: BTreeMap::from([(
                NATIVE_PROGRAM,
                if balance == 0 {
                    vec![]
                } else {
                    balance.to_le_bytes().to_vec()
                },
            )]),
        },
    }
}
struct Fixture {
    memory: Memory,
    wallet: Wallet<Memory>,
    policy: Policy,
    app: AppId,
    key: PrivateKey,
    transfer: NativeTransfer,
}
fn fixture() -> Fixture {
    let key = PrivateKey::try_new([1; 32]).unwrap();
    let to = id(&PrivateKey::try_new([2; 32]).unwrap());
    let from = id(&key);
    let memory = Memory {
        views: Rc::new(RefCell::new(BTreeMap::from([
            (from, view(100_000)),
            (to, view(0)),
        ]))),
        quote: Rc::new(RefCell::new(FeeQuote {
            height: 10,
            base_fee_exec: 8,
            base_fee_stor: 8,
            next_base_fee_exec_floor: 8,
            next_base_fee_exec_ceiling: 9,
            next_base_fee_stor_floor: 8,
            next_base_fee_stor_ceiling: 9,
            max_gas_exec: 10_000_000,
            max_gas_stor: 1_000_000,
        })),
        reads: Rc::new(Cell::new(0)),
    };
    let app = AppId("fixture-v03-consumer".into());
    let mut policy = Policy::default();
    policy
        .set_grant(
            app.clone(),
            Grant {
                accounts: [from.bytes()].into(),
                scopes: [Scope::Transactions].into(),
            },
        )
        .unwrap();
    let wallet = Wallet::new(memory.clone(), "http://127.0.0.1:3040").unwrap();
    Fixture {
        memory,
        wallet,
        policy,
        app,
        key,
        transfer: NativeTransfer {
            from,
            to,
            amount: 100,
            gas_limit: 1000,
            tip: 3,
            max_fee: 20_000,
        },
    }
}
#[test]
fn approved_native_transfer_executes_in_upstream_state_machine_and_replay_fails() {
    let mut f = fixture();
    let prepared = f
        .wallet
        .prepare_native(&mut f.policy, &f.app, f.transfer, 100)
        .unwrap();
    let Request::Transaction(review) = &prepared.prompt().request else {
        panic!("missing transaction")
    };
    assert!(
        matches!(&review.effects[0],Effect::NativeTransfer{amount,destination} if amount=="100" && destination==&f.transfer.to.bytes())
    );
    assert!(
        matches!(&review.effects[1],Effect::ContractCall{explanation,..} if explanation.contains("20000") && explanation.contains("tip 3") && explanation.contains("1000"))
    );
    assert!(
        f.wallet
            .sign_approved(&mut f.policy, &f.app, &prepared, &f.key, 101)
            .is_err()
    );
    f.policy.decide(prepared.prompt().id, true, 101).unwrap();
    let signed = f
        .wallet
        .sign_approved(&mut f.policy, &f.app, &prepared, &f.key, 102)
        .unwrap();
    assert!(lee_v03::is_fee_authorized(
        signed.message(),
        signed.witness_set()
    ));
    assert_eq!(
        prepared.wire_bytes() as usize,
        borsh::to_vec(&signed).unwrap().len() + 1
    );
    assert!(
        f.wallet
            .sign_approved(&mut f.policy, &f.app, &prepared, &f.key, 103)
            .is_err()
    );
    let from = lee_v03::AccountId::new(f.transfer.from.bytes());
    let to = lee_v03::AccountId::new(f.transfer.to.bytes());
    let mut state = V03State::new().with_public_account_balances([(from, 100_000)]);
    state
        .transition_from_public_transaction(&signed, 1, 0)
        .unwrap();
    // Core execution does not settle sequencer fees. Verify native action only.
    assert_eq!(
        state.get_account_by_id(from).data.native_balance().unwrap(),
        99_900
    );
    assert_eq!(
        state.get_account_by_id(to).data.native_balance().unwrap(),
        100
    );
    assert_eq!(state.get_account_by_id(from).nonce.0, 1);
    assert_eq!(state.get_account_by_id(to).nonce.0, 0);
    assert!(
        state
            .transition_from_public_transaction(&signed, 2, 0)
            .is_err()
    );
    let mut tampered = signed;
    tampered.message.fee.as_mut().unwrap().max_fee += 1;
    assert!(!tampered.witness_set.is_valid_for(&tampered.message));
}
#[test]
fn changed_nonce_balance_fee_and_revoked_access_cannot_be_signed() {
    for change in 0..4 {
        let mut f = fixture();
        let prepared = f
            .wallet
            .prepare_native(&mut f.policy, &f.app, f.transfer, 100)
            .unwrap();
        f.policy.decide(prepared.prompt().id, true, 101).unwrap();
        match change {
            0 => {
                f.memory
                    .views
                    .borrow_mut()
                    .get_mut(&f.transfer.from)
                    .unwrap()
                    .nonce = 1
            }
            1 => {
                f.memory
                    .views
                    .borrow_mut()
                    .insert(f.transfer.from, view(100));
            }
            2 => f.memory.quote.borrow_mut().next_base_fee_exec_ceiling = 100,
            _ => f.policy.revoke(&f.app),
        }
        assert!(
            f.wallet
                .sign_approved(&mut f.policy, &f.app, &prepared, &f.key, 102)
                .is_err()
        );
    }
}
#[test]
fn wrong_key_endpoint_app_and_expired_approval_are_rejected() {
    let mut f = fixture();
    let prepared = f
        .wallet
        .prepare_native(&mut f.policy, &f.app, f.transfer, 100)
        .unwrap();
    f.policy.decide(prepared.prompt().id, true, 101).unwrap();
    let other = PrivateKey::try_new([3; 32]).unwrap();
    assert!(
        f.wallet
            .sign_approved(&mut f.policy, &f.app, &prepared, &other, 102)
            .is_err()
    );
    let other_wallet = Wallet::new(f.memory.clone(), "http://127.0.0.1:3041").unwrap();
    assert!(
        other_wallet
            .sign_approved(&mut f.policy, &f.app, &prepared, &f.key, 102)
            .is_err()
    );
    assert!(
        f.wallet
            .sign_approved(
                &mut f.policy,
                &AppId("other".into()),
                &prepared,
                &f.key,
                102
            )
            .is_err()
    );
    assert!(
        f.wallet
            .sign_approved(
                &mut f.policy,
                &f.app,
                &prepared,
                &f.key,
                prepared.prompt().expires_at
            )
            .is_err()
    );
}
#[test]
fn permission_and_invalid_amount_fail_before_network_reads() {
    let mut f = fixture();
    f.policy.revoke(&f.app);
    assert!(
        f.wallet
            .prepare_native(&mut f.policy, &f.app, f.transfer, 100)
            .is_err()
    );
    assert_eq!(f.memory.reads.get(), 0);
    let mut f = fixture();
    f.transfer.amount = 0;
    assert!(
        f.wallet
            .prepare_native(&mut f.policy, &f.app, f.transfer, 100)
            .is_err()
    );
    assert_eq!(f.memory.reads.get(), 0);
}
#[test]
fn fee_budget_gas_caps_and_recipient_overflow_fail_preparation() {
    for change in 0..4 {
        let mut f = fixture();
        match change {
            0 => f.transfer.max_fee = 1,
            1 => f.transfer.gas_limit = 10_000_001,
            2 => {
                f.memory
                    .views
                    .borrow_mut()
                    .insert(f.transfer.to, view(u128::MAX));
            }
            _ => f.transfer.max_fee = u128::MAX,
        }
        assert!(
            f.wallet
                .prepare_native(&mut f.policy, &f.app, f.transfer, 100)
                .is_err()
        );
    }
}
