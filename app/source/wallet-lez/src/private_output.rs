// SPDX-License-Identifier: MIT OR Apache-2.0
//! Commitments are sorted independently of nullifier/encrypted-note pairs by
//! the pinned circuit. A note's array position does not identify its commitment.
use key_protocol::key_management::secret_holders::PrivateKeyHolder;
use lee::{Account, AccountId};
use lee_core::{
    Commitment, EncryptionScheme, Nullifier, PrivateAccountKind, PrivateAction, SharedSecretKey,
    account::Nonce,
};

pub(crate) fn exact_commitments(
    actions: &[PrivateAction],
    expected: impl IntoIterator<Item = Commitment>,
) -> bool {
    let mut actual: Vec<_> = actions
        .iter()
        .map(|action| action.commitment.to_byte_array())
        .collect();
    let mut expected: Vec<_> = expected
        .into_iter()
        .map(|value| value.to_byte_array())
        .collect();
    actual.sort_unstable();
    expected.sort_unstable();
    actual == expected && expected.windows(2).all(|pair| pair[0] != pair[1])
}
pub(crate) enum Expected<'a> {
    Recorded(&'a Account),
    Successor { nullifier: Nullifier, nonce: Nonce },
}
pub(crate) fn recover(
    actions: &[PrivateAction],
    keys: &PrivateKeyHolder,
    kind: &PrivateAccountKind,
    account: AccountId,
    expected: Expected<'_>,
) -> Option<Account> {
    let mut found = None;
    for action in actions {
        if matches!(&expected,Expected::Successor{nullifier,..} if action.nullifier!=*nullifier) {
            continue;
        }
        let Some(secret) = SharedSecretKey::decapsulate(
            &action.encrypted_post_state.epk,
            &keys.viewing_secret_key.d,
            &keys.viewing_secret_key.z,
        ) else {
            continue;
        };
        let Some((actual_kind, state)) = EncryptionScheme::decrypt(
            &action.encrypted_post_state.ciphertext,
            &secret,
            &action.nullifier,
        ) else {
            continue;
        };
        if actual_kind != *kind {
            continue;
        }
        let matches = match &expected {
            Expected::Recorded(record) => state == **record,
            Expected::Successor { nonce, .. } => state.nonce == *nonce,
        };
        if !matches {
            continue;
        }
        let commitment = Commitment::new(&account, &state);
        if actions
            .iter()
            .filter(|candidate| candidate.commitment == commitment)
            .count()
            != 1
            || found.is_some()
        {
            return None;
        }
        found = Some(state);
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use key_protocol::key_management::secret_holders::SecretSpendingKey;
    use lee_core::{EncryptedAccountData, EphemeralSecretKey};
    fn note(
        tag: u8,
    ) -> (
        PrivateKeyHolder,
        AccountId,
        PrivateAccountKind,
        Account,
        PrivateAction,
    ) {
        let keys = SecretSpendingKey([tag; 32]).produce_private_key_holder(None);
        let kind = PrivateAccountKind::Regular(u128::from(tag));
        let vpk = keys.generate_viewing_public_key();
        let account =
            AccountId::for_private_account(&keys.generate_nullifier_public_key(), &vpk, &kind);
        let before = Account {
            balance: 100,
            ..Account::default()
        };
        let nullifier = Nullifier::for_account_update(
            &Commitment::new(&account, &before),
            &keys.nullifier_secret_key,
        );
        let state = Account {
            balance: 99,
            nonce: before
                .nonce
                .private_account_nonce_increment(&keys.nullifier_secret_key),
            ..before
        };
        let esk = EphemeralSecretKey::new(&account, &[tag; 32], &state.nonce);
        let (secret, epk) = SharedSecretKey::encapsulate_deterministic(&vpk, &esk);
        let action = PrivateAction {
            nullifier,
            root: [0; 32],
            commitment: Commitment::new(&account, &state),
            encrypted_post_state: EncryptedAccountData {
                ciphertext: EncryptionScheme::encrypt(&state, &kind, &secret, &nullifier),
                epk,
                view_tag: tag,
            },
        };
        (keys, account, kind, state, action)
    }
    #[test]
    fn independently_ordered_commitments_recover_recorded_and_successor_notes() {
        let (keys, account, kind, state, first) = note(1);
        let (_, _, _, _, second) = note(2);
        let commitments = [first.commitment, second.commitment];
        let mut actions = [first, second];
        // Force the association the old validator incorrectly rejected.
        actions[0].commitment = commitments[1];
        actions[1].commitment = commitments[0];
        assert!(exact_commitments(&actions, commitments));
        assert_eq!(
            recover(&actions, &keys, &kind, account, Expected::Recorded(&state)),
            Some(state.clone())
        );
        assert_eq!(
            recover(
                &actions,
                &keys,
                &kind,
                account,
                Expected::Successor {
                    nullifier: actions[0].nullifier,
                    nonce: state.nonce
                }
            ),
            Some(state)
        );
    }
    #[test]
    fn shuffled_outputs_still_reject_missing_duplicate_tampered_and_stale_state() {
        let (keys, account, kind, state, first) = note(3);
        let (_, _, _, _, second) = note(4);
        let commitments = [first.commitment, second.commitment];
        let mut actions = [first, second];
        actions[0].commitment = commitments[1];
        actions[1].commitment = commitments[0];
        let mut wrong_state = state.clone();
        wrong_state.balance += 1;
        assert!(
            recover(
                &actions,
                &keys,
                &kind,
                account,
                Expected::Recorded(&wrong_state)
            )
            .is_none()
        );
        assert!(
            recover(
                &actions,
                &keys,
                &kind,
                account,
                Expected::Successor {
                    nullifier: actions[0].nullifier,
                    nonce: 0.into()
                }
            )
            .is_none()
        );
        assert!(
            recover(
                &actions,
                &keys,
                &PrivateAccountKind::Regular(999),
                account,
                Expected::Recorded(&state)
            )
            .is_none()
        );
        let mut missing = actions.clone();
        missing[1].commitment = commitments[1];
        assert!(!exact_commitments(&missing, commitments));
        assert!(recover(&missing, &keys, &kind, account, Expected::Recorded(&state)).is_none());
        let mut duplicate = actions.to_vec();
        duplicate.push(actions[1].clone());
        assert!(!exact_commitments(&duplicate, commitments));
        assert!(
            recover(
                &duplicate,
                &keys,
                &kind,
                account,
                Expected::Recorded(&state)
            )
            .is_none()
        );
        let mut tampered = actions;
        let mut bytes = borsh::to_vec(&tampered[0].encrypted_post_state.ciphertext).unwrap();
        bytes[4] ^= 1; // First ciphertext byte after the Borsh vector length.
        tampered[0].encrypted_post_state.ciphertext = borsh::from_slice(&bytes).unwrap();
        assert!(recover(&tampered, &keys, &kind, account, Expected::Recorded(&state)).is_none());
    }
}
