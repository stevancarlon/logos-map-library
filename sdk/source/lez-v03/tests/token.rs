// SPDX-License-Identifier: MIT OR Apache-2.0
use lee_v03::{PrivateKey, PublicKey};
use logos_lez_v03::{
    AccountData, AccountId, AccountView, Error, FeeQuote, NATIVE_PROGRAM, Result,
    token::{
        self, TokenDefinition, TokenHolding, TokenKind, TokenReader, TokenTransfer, TokenWallet,
    },
    transfer::NativeReader,
};
use logos_wallet_policy::{AppId, Grant, Policy, Request, Scope};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::Rc,
};
#[derive(Clone)]
struct Memory {
    data: Rc<RefCell<BTreeMap<AccountId, Vec<u8>>>>,
    nonce: Rc<Cell<u128>>,
    native: Rc<Cell<u128>>,
    reads: Rc<Cell<usize>>,
    program: Rc<Cell<bool>>,
    fee: Rc<Cell<u64>>,
}
impl NativeReader for Memory {
    fn native_view(&self, _: AccountId) -> Result<AccountView> {
        self.reads.set(self.reads.get() + 1);
        Ok(AccountView {
            nonce: self.nonce.get(),
            data: AccountData {
                shards: BTreeMap::from([(
                    NATIVE_PROGRAM,
                    self.native.get().to_le_bytes().to_vec(),
                )]),
            },
        })
    }
    fn fees(&self) -> Result<FeeQuote> {
        Ok(FeeQuote {
            height: 1,
            base_fee_exec: self.fee.get(),
            base_fee_stor: 8,
            next_base_fee_exec_floor: 8,
            next_base_fee_exec_ceiling: self.fee.get() + 1,
            next_base_fee_stor_floor: 8,
            next_base_fee_stor_ceiling: 9,
            max_gas_exec: 10_000_000,
            max_gas_stor: 1_000_000,
        })
    }
}
impl TokenReader for Memory {
    fn token_view(&self, account: AccountId) -> Result<AccountView> {
        self.reads.set(self.reads.get() + 1);
        Ok(AccountView {
            nonce: self.nonce.get(),
            data: AccountData {
                shards: BTreeMap::from([(
                    token::program(),
                    self.data
                        .borrow()
                        .get(&account)
                        .cloned()
                        .unwrap_or_default(),
                )]),
            },
        })
    }
    fn verify_token_program(&self) -> Result<()> {
        self.reads.set(self.reads.get() + 1);
        if self.program.get() {
            Ok(())
        } else {
            Err(Error::Invalid("fixture program changed"))
        }
    }
}
struct Fixture {
    reader: Memory,
    wallet: TokenWallet<Memory>,
    policy: Policy,
    app: AppId,
    key: PrivateKey,
    t: TokenTransfer,
}
fn up(id: AccountId) -> lee_v03::AccountId {
    lee_v03::AccountId::new(id.bytes())
}
fn fixture(kind: TokenKind) -> Fixture {
    let key = PrivateKey::try_new([1; 32]).unwrap();
    let from = AccountId::from_bytes(
        *lee_v03::AccountId::from(&PublicKey::new_from_private_key(&key)).value(),
    );
    let definition = AccountId::from_bytes([5; 32]);
    let (def, holding, amount) = match kind {
        TokenKind::Fungible => (
            TokenDefinition::Fungible {
                name: "Fixture".into(),
                total_supply: 1000,
                metadata_id: None,
            },
            TokenHolding::Fungible {
                definition_id: up(definition),
                balance: 100,
            },
            10,
        ),
        TokenKind::NftMaster => (
            TokenDefinition::NonFungible {
                name: "Fixture".into(),
                printable_supply: 7,
                metadata_id: up(AccountId::from_bytes([6; 32])),
            },
            TokenHolding::NftMaster {
                definition_id: up(definition),
                print_balance: 7,
            },
            7,
        ),
        TokenKind::NftPrintedCopy => (
            TokenDefinition::NonFungible {
                name: "Fixture".into(),
                printable_supply: 7,
                metadata_id: up(AccountId::from_bytes([6; 32])),
            },
            TokenHolding::NftPrintedCopy {
                definition_id: up(definition),
                owned: true,
            },
            1,
        ),
    };
    let reader = Memory {
        data: Rc::new(RefCell::new(BTreeMap::from([
            (from, borsh::to_vec(&holding).unwrap()),
            (definition, borsh::to_vec(&def).unwrap()),
        ]))),
        nonce: Rc::new(Cell::new(4)),
        native: Rc::new(Cell::new(1_000_000)),
        reads: Rc::new(Cell::new(0)),
        program: Rc::new(Cell::new(true)),
        fee: Rc::new(Cell::new(8)),
    };
    let wallet = TokenWallet::new(reader.clone(), "http://127.0.0.1:3090").unwrap();
    let app = AppId("fixture-token".into());
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
    Fixture {
        reader,
        wallet,
        policy,
        app,
        key,
        t: TokenTransfer {
            from,
            to: AccountId::from_bytes([2; 32]),
            definition,
            kind,
            amount,
            gas_limit: 1000,
            tip: 7,
            max_fee: 20_000,
        },
    }
}
#[test]
fn all_asset_types_use_exact_upstream_instruction_one_signer_and_one_use_approval() {
    for kind in [
        TokenKind::Fungible,
        TokenKind::NftMaster,
        TokenKind::NftPrintedCopy,
    ] {
        let mut f = fixture(kind);
        let prepared = f.wallet.prepare(&mut f.policy, &f.app, f.t, 100).unwrap();
        assert!(
            f.wallet
                .sign_approved(&mut f.policy, &f.app, &prepared, &f.key, 101)
                .is_err()
        );
        f.policy.decide(prepared.prompt().id, true, 101).unwrap();
        let tx = f
            .wallet
            .sign_approved(&mut f.policy, &f.app, &prepared, &f.key, 102)
            .unwrap();
        assert!(tx.witness_set.is_valid_for(&tx.message));
        assert_eq!(tx.message.nonces, vec![4u128.into()]);
        assert_eq!(tx.witness_set.signatures_and_public_keys().len(), 1);
        let token_core_v03::Instruction::Transfer {
            amount_to_transfer,
            descriptor,
        } = borsh::from_slice(&tx.message.instruction_data).unwrap()
        else {
            panic!("wrong instruction")
        };
        assert_eq!(amount_to_transfer, f.t.amount);
        assert_eq!(descriptor.kind, kind);
        assert_eq!(descriptor.definition_id, up(f.t.definition));
        assert_eq!(tx.message.fee.unwrap().max_fee, 20_000);
        let mut tampered = tx.clone();
        tampered.message.fee.as_mut().unwrap().tip += 1;
        assert!(!tampered.witness_set.is_valid_for(&tampered.message));
        assert!(
            f.wallet
                .sign_approved(&mut f.policy, &f.app, &prepared, &f.key, 103)
                .is_err()
        );
        let Request::Transaction(review) = &prepared.prompt().request else {
            panic!("wrong review")
        };
        assert_eq!(review.account, f.t.from.bytes());
        let rendered = serde_json::to_string(&review.effects).unwrap();
        assert!(rendered.contains("public transfer"));
        if kind == TokenKind::NftMaster {
            assert!(rendered.contains("6 remaining print rights"));
        }
    }
}
#[test]
fn permissions_and_invalid_input_fail_before_network_reads() {
    let mut f = fixture(TokenKind::Fungible);
    f.policy.revoke(&f.app);
    assert!(f.wallet.prepare(&mut f.policy, &f.app, f.t, 100).is_err());
    assert_eq!(f.reader.reads.get(), 0);
    for change in [0, 1, 2] {
        let mut f = fixture(TokenKind::Fungible);
        match change {
            0 => f.t.amount = 0,
            1 => f.t.to = f.t.from,
            _ => f.t.to = f.t.definition,
        }
        assert!(f.wallet.prepare(&mut f.policy, &f.app, f.t, 100).is_err());
        assert_eq!(f.reader.reads.get(), 0);
    }
}
#[test]
fn changed_nonce_program_native_balance_and_fee_invalidate_signing() {
    for change in 0..5 {
        let mut f = fixture(TokenKind::Fungible);
        let p = f.wallet.prepare(&mut f.policy, &f.app, f.t, 100).unwrap();
        f.policy.decide(p.prompt().id, true, 101).unwrap();
        match change {
            0 => f.reader.nonce.set(5),
            1 => f.reader.program.set(false),
            2 => f.reader.native.set(1),
            3 => f.reader.fee.set(100),
            _ => f.policy.revoke(&f.app),
        }
        assert!(
            f.wallet
                .sign_approved(&mut f.policy, &f.app, &p, &f.key, 102)
                .is_err()
        );
    }
    let mut f = fixture(TokenKind::Fungible);
    let p = f.wallet.prepare(&mut f.policy, &f.app, f.t, 100).unwrap();
    f.policy.decide(p.prompt().id, true, 101).unwrap();
    assert!(
        f.wallet
            .sign_approved(
                &mut f.policy,
                &f.app,
                &p,
                &PrivateKey::try_new([2; 32]).unwrap(),
                102
            )
            .is_err()
    );
    let other = TokenWallet::new(f.reader.clone(), "http://127.0.0.1:3091").unwrap();
    assert!(
        other
            .sign_approved(&mut f.policy, &f.app, &p, &f.key, 102)
            .is_err()
    );
}
#[test]
fn mismatched_collection_kind_and_overflow_reject_recipients() {
    let bad = [
        TokenHolding::Fungible {
            definition_id: up(AccountId::from_bytes([8; 32])),
            balance: 0,
        },
        TokenHolding::Fungible {
            definition_id: up(AccountId::from_bytes([5; 32])),
            balance: u128::MAX,
        },
        TokenHolding::NftMaster {
            definition_id: up(AccountId::from_bytes([5; 32])),
            print_balance: 0,
        },
    ];
    for holding in bad {
        let mut f = fixture(TokenKind::Fungible);
        f.reader
            .data
            .borrow_mut()
            .insert(f.t.to, borsh::to_vec(&holding).unwrap());
        assert!(f.wallet.prepare(&mut f.policy, &f.app, f.t, 100).is_err());
    }
    let mut f = fixture(TokenKind::Fungible);
    f.t.amount = 101;
    assert!(f.wallet.prepare(&mut f.policy, &f.app, f.t, 100).is_err());
}
#[test]
fn master_and_copy_transfers_require_actual_ownership_and_empty_destination() {
    for kind in [TokenKind::NftMaster, TokenKind::NftPrintedCopy] {
        let mut f = fixture(kind);
        f.t.amount += 1;
        assert!(f.wallet.prepare(&mut f.policy, &f.app, f.t, 100).is_err());
        let mut f = fixture(kind);
        let state = if kind == TokenKind::NftMaster {
            TokenHolding::NftMaster {
                definition_id: up(f.t.definition),
                print_balance: 1,
            }
        } else {
            TokenHolding::NftPrintedCopy {
                definition_id: up(f.t.definition),
                owned: true,
            }
        };
        f.reader
            .data
            .borrow_mut()
            .insert(f.t.to, borsh::to_vec(&state).unwrap());
        assert!(f.wallet.prepare(&mut f.policy, &f.app, f.t, 100).is_err());
        let mut f = fixture(kind);
        let state = token_core_v03::TokenDescriptor {
            definition_id: up(f.t.definition),
            kind,
        }
        .zeroized();
        f.reader
            .data
            .borrow_mut()
            .insert(f.t.from, borsh::to_vec(&state).unwrap());
        assert!(f.wallet.prepare(&mut f.policy, &f.app, f.t, 100).is_err());
    }
}
#[test]
fn readers_reject_legacy_wrong_shard_and_trailing_encodings() {
    let f = fixture(TokenKind::Fungible);
    let mut view = f.reader.token_view(f.t.from).unwrap();
    view.data.shards.get_mut(&token::program()).unwrap().push(0);
    assert!(token::holding(&view).is_err());
    let native = f.reader.native_view(f.t.from).unwrap();
    assert!(token::holding(&native).is_err());
    assert!(token::definition(&native).is_err());
}
