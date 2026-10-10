// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::{AccountData, AccountView, FeeQuote, NATIVE_PROGRAM};
use lee_core_v03::{EncryptionScheme, PrivateAction, PublicAction};
use logos_wallet_policy::Grant;
use std::{cell::Cell, collections::BTreeMap};
fn identity() -> PrivateIdentity {
    PrivateIdentity::from_seed(Zeroizing::new([7; 32]), [8; 32])
}
fn public() -> AccountId {
    AccountId::from_bytes([9; 32])
}
struct Peer {
    reads: Cell<u32>,
    commitment: Option<Commitment>,
}
impl NativeReader for Peer {
    fn native_view(&self, _: AccountId) -> Result<AccountView> {
        self.reads.set(self.reads.get() + 1);
        Ok(AccountView {
            nonce: 3,
            data: AccountData {
                shards: BTreeMap::from([(NATIVE_PROGRAM, 1000u128.to_le_bytes().to_vec())]),
            },
        })
    }
    fn fees(&self) -> Result<FeeQuote> {
        Err(Error::Invalid(
            "private preparation must not invent a fee declaration",
        ))
    }
}
impl PrivateReader for Peer {
    fn proofs_and_root(
        &self,
        cs: &[Commitment],
    ) -> Result<(Vec<Option<MembershipProof>>, [u8; 32])> {
        self.reads.set(self.reads.get() + 1);
        let root = self
            .commitment
            .map(|c| Sha256::digest(c.to_byte_array()).into())
            .unwrap_or(lee_core_v03::DUMMY_COMMITMENT_HASH);
        Ok((
            cs.iter()
                .map(|c| {
                    (*c == self.commitment.unwrap_or(lee_core_v03::DUMMY_COMMITMENT))
                        .then(|| (0, vec![]))
                })
                .collect(),
            root,
        ))
    }
}
impl ShieldedReader for Peer {
    fn endpoint(&self) -> &str {
        "http://127.0.0.1:3090"
    }
    fn verify_privacy_circuit(&self) -> Result<()> {
        self.reads.set(self.reads.get() + 1);
        Ok(())
    }
}
fn policy(id: &PrivateIdentity) -> (Policy, AppId) {
    let app = AppId("synthetic-private".into());
    let mut policy = Policy::default();
    policy
        .set_grant(
            app.clone(),
            Grant {
                accounts: [public().bytes(), id.account().bytes()].into(),
                scopes: [Scope::Transactions].into(),
            },
        )
        .unwrap();
    (policy, app)
}
#[test]
fn private_identity_uses_pinned_index_zero_key_domains_and_opaque_identifiers() {
    let id = identity();
    id.with_keys(|keys| {
        // Independently computed Python hashlib/hmac vectors for synthetic [7;32].
        assert_eq!(
            hex::encode(keys.authorization_secret_key.0),
            "6c9dfc5a3c4c2262594464a2758079dd34cc5ea33edfe679a930c8892d030d15"
        );
        assert_eq!(
            hex::encode(keys.d),
            "28f2ba26db898681058114b4084eb5ab0184f929035eb1859d54388c4fb18a65"
        );
        assert_eq!(
            hex::encode(keys.z),
            "5b4e22c7504f53612517cf4fe7ac1a1591121b9a41ef068c40d527815e97cc31"
        );
        assert_eq!(
            id.account(),
            AccountId::from_bytes(
                *lee_v03::AccountId::for_regular_private_account(
                    &keys.generate_nullifier_public_key(),
                    &keys.generate_viewing_public_key(),
                    Identifier::new([8; 32])
                )
                .value()
            )
        );
    });
    let recovered: PrivateIdentity =
        serde_json::from_slice(&serde_json::to_vec(&id).unwrap()).unwrap();
    assert_eq!(id.account(), recovered.account());
    assert_ne!(
        id.account(),
        PrivateIdentity::from_seed(Zeroizing::new([7; 32]), [9; 32]).account()
    );
    assert_ne!(
        id.account(),
        PrivateIdentity::from_seed(Zeroizing::new([8; 32]), [8; 32]).account()
    );
}
#[test]
fn quiet_note_decoder_matches_upstream_padding_and_rejects_malformed_lengths() {
    let nullifier = Nullifier::for_account_initialization(&up(identity().account()));
    let secret = SharedSecretKey([3; 32]);
    let kind = PrivateAccountKind::Regular(Identifier::new([8; 32]));
    let account = Account::funded(u128::MAX).with_shard(
        lee_v03::AccountId::new([4; 32]),
        vec![8; 99].try_into().unwrap(),
    );
    for padding in [None, Some(512), Some(8192)] {
        let ct = EncryptionScheme::encrypt(&account, &kind, &secret, &nullifier, padding);
        let (got_kind, got) = decrypt_quiet(&ct, &secret, &nullifier).unwrap();
        assert_eq!(got_kind, kind);
        assert_eq!(got, account);
    }
    let mut ct =
        EncryptionScheme::encrypt(&account, &kind, &secret, &nullifier, Some(512)).into_inner();
    *ct.last_mut().unwrap() ^= 1;
    assert!(decrypt_quiet(&Ciphertext::from_inner(ct), &secret, &nullifier).is_err());
    let mut ct =
        EncryptionScheme::encrypt(&account, &kind, &secret, &nullifier, Some(512)).into_inner();
    for i in 0..4 {
        ct[PrivateAccountKind::HEADER_LEN + 16 + i] ^= 0xff;
    }
    assert!(decrypt_quiet(&Ciphertext::from_inner(ct), &secret, &nullifier).is_err());
    assert!(
        decrypt_quiet(
            &Ciphertext::from_inner(vec![0; 128 * 1024 + 1]),
            &secret,
            &nullifier
        )
        .is_err()
    );
    assert!(decrypt_quiet(&Ciphertext::from_inner(vec![0; 8]), &secret, &nullifier).is_err());
}
#[test]
fn commitment_lookup_rejects_substitution_counts_depth_and_unused_index_bits() {
    let c = Commitment::new(&up(identity().account()), &Account::funded(10));
    let proof = (0, vec![]);
    let root = lee_core_v03::compute_digest_for_path(&c, &proof);
    assert!(validate_memberships(&[c], &[Some(proof.clone())], root).is_ok());
    assert!(validate_memberships(&[c], &[None], root).is_ok());
    assert!(validate_memberships(&[c], &[], root).is_err());
    assert!(validate_memberships(&[c], &[Some((1, vec![]))], root).is_err());
    assert!(validate_memberships(&[c], &[Some((0, vec![[0; 32]; 65]))], root).is_err());
    assert!(validate_memberships(&[c], &[Some(proof)], [0; 32]).is_err());
}
#[test]
fn private_preparation_requires_permissions_and_an_existing_withdrawal_opening() {
    let id = identity();
    let peer = Peer {
        reads: Cell::new(0),
        commitment: None,
    };
    let (mut policy, app) = policy(&id);
    let operation = NativeOperation {
        public_account: public(),
        direction: Direction::Deposit,
        amount: 15,
    };
    assert!(
        prepare_native(
            &mut Policy::default(),
            &app,
            &peer,
            &id,
            None,
            operation,
            10
        )
        .is_err()
    );
    assert_eq!(peer.reads.get(), 0);
    let prepared = prepare_native(&mut policy, &app, &peer, &id, None, operation, 10).unwrap();
    assert_eq!(prepared.after.data.native_balance().unwrap(), 15);
    assert_eq!(
        prepared.after.nonce,
        Nonce::private_account_nonce_init(&up(id.account()))
    );
    assert!(
        prepare_native(
            &mut policy,
            &app,
            &peer,
            &id,
            None,
            NativeOperation {
                direction: Direction::Withdrawal,
                ..operation
            },
            10
        )
        .is_err()
    );
    let before = Account::funded(20);
    let peer = Peer {
        reads: Cell::new(0),
        commitment: Some(Commitment::new(&up(id.account()), &before)),
    };
    let withdrawal = prepare_native(
        &mut policy,
        &app,
        &peer,
        &id,
        Some(&before),
        NativeOperation {
            direction: Direction::Withdrawal,
            ..operation
        },
        10,
    )
    .unwrap();
    assert_eq!(withdrawal.after.data.native_balance().unwrap(), 5);
    assert!(
        prepare_native(
            &mut policy,
            &app,
            &peer,
            &id,
            Some(&before),
            NativeOperation {
                direction: Direction::Withdrawal,
                amount: 21,
                ..operation
            },
            10
        )
        .is_err()
    );
}
#[test]
fn private_output_validation_matches_commitments_as_a_set_not_by_row() {
    let id = identity();
    let peer = Peer {
        reads: Cell::new(0),
        commitment: None,
    };
    let (mut policy, app) = policy(&id);
    let prepared = prepare_native(
        &mut policy,
        &app,
        &peer,
        &id,
        None,
        NativeOperation {
            public_account: public(),
            direction: Direction::Deposit,
            amount: 15,
        },
        10,
    )
    .unwrap();
    let (input, dummy) = dummy(prepared.root).unwrap();
    let view_tag = 42;
    let (shared, epk) =
        id.with_keys(|keys| SharedSecretKey::encapsulate(&keys.generate_viewing_public_key()));
    let real_note = EncryptedAccountData {
        ciphertext: EncryptionScheme::encrypt(
            &prepared.after,
            &PrivateAccountKind::Regular(id.identifier()),
            &shared,
            &prepared.nullifier,
            Some(512),
        ),
        epk,
        view_tag,
    };
    let real_commitment = Commitment::new(&up(id.account()), &prepared.after);
    let output = PrivacyPreservingCircuitOutput {
        public_actions: vec![PublicAction {
            account_id: up(public()),
            is_authorized: true,
            effects: vec![lee_core_v03::execution_state::DeferredPublicEffect {
                program_account_id: native_token::NATIVE_TOKEN_PROGRAM_ID,
                shard_program_account_id: native_token::NATIVE_TOKEN_PROGRAM_ID,
                data: borsh::to_vec(&native_token::Effect::Debit(15)).unwrap(),
            }],
        }],
        private_actions: vec![
            PrivateAction {
                nullifier: prepared.nullifier,
                root: prepared.root,
                commitment: dummy.commitment,
                encrypted_post_state: real_note,
            },
            PrivateAction {
                nullifier: dummy.nullifier,
                root: prepared.root,
                commitment: real_commitment,
                encrypted_post_state: input.note,
            },
        ],
        ..Default::default()
    };
    assert!(
        validate_output(
            &output,
            &prepared,
            &id,
            std::slice::from_ref(&dummy),
            view_tag
        )
        .is_ok()
    );
    for field in 0..5 {
        let mut changed: PrivacyPreservingCircuitOutput =
            borsh::from_slice(&borsh::to_vec(&output).unwrap()).unwrap();
        match field {
            0 => changed.private_actions[0].commitment = real_commitment,
            1 => changed.private_actions[0].root = [9; 32],
            2 => changed.private_actions[0].encrypted_post_state.view_tag ^= 1,
            3 => changed.public_actions[0].is_authorized = false,
            _ => {
                changed.public_actions[0].effects[0].data =
                    borsh::to_vec(&native_token::Effect::Debit(16)).unwrap()
            }
        };
        assert!(
            validate_output(
                &changed,
                &prepared,
                &id,
                std::slice::from_ref(&dummy),
                view_tag
            )
            .is_err()
        );
    }
    assert!(verify_receipt(&output, &circuit::Proof::from_inner(vec![0; 8])).is_err());
    let fake = risc0_zkvm::InnerReceipt::Fake(risc0_zkvm::FakeReceipt::new(
        risc0_zkvm::ReceiptClaim::ok(lee_v03::PRIVACY_PRESERVING_CIRCUIT_ID, output.to_bytes()),
    ));
    assert!(
        verify_receipt(
            &output,
            &circuit::Proof::from_inner(borsh::to_vec(&fake).unwrap())
        )
        .is_err()
    );
}
#[test]
fn private_prover_configuration_requires_real_local_execution() {
    assert!(check_local_configuration(Some("ipc"), Some("ipc"), Some("0")).is_ok());
    for (prover, executor, dev) in [
        (Some("bonsai"), Some("ipc"), Some("0")),
        (None, Some("ipc"), Some("0")),
        (Some("ipc"), None, Some("0")),
        (Some("ipc"), Some("ipc"), Some("1")),
        (Some("ipc"), Some("ipc"), None),
    ] {
        assert!(check_local_configuration(prover, executor, dev).is_err());
    }
}
