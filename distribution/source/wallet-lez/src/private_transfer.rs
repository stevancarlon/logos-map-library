// SPDX-License-Identifier: MIT OR Apache-2.0
//! Transfers between two initialized private accounts owned by this wallet.
//! Trusted API only: account openings and keys must never come from dApp input.
use crate::{
    shielded::{Error, Result, require_local_prover},
    shielded_transfer::{self, Asset, Direction, Proven, Transfer},
};
use key_protocol::key_management::secret_holders::PrivateKeyHolder;
use lee::{
    Account, AccountId, PrivacyPreservingTransaction,
    privacy_preserving_transaction::{circuit, message::Message, witness_set::WitnessSet},
};
use lee_core::{
    Commitment, EncryptionScheme, InputAccountIdentity, MembershipProof, Nullifier,
    PrivateAccountKind, SharedSecretKey, account::AccountWithMetadata,
};
use logos_registry_sdk::HttpNode;
use logos_wallet_policy::{AppId, Effect, Policy, Prompt, Request, Scope, Transaction};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

pub struct Opening {
    pub account: AccountId,
    pub state: Account,
    pub identifier: u128,
}
pub struct TransferRequest {
    pub from: Opening,
    pub to: Opening,
    pub asset: Asset,
    pub amount: u128,
}
pub struct Prepared {
    prompt: Prompt,
    request: TransferRequest,
    memberships: [MembershipProof; 2],
    root: [u8; 32],
    expected: [Account; 2],
}
impl Prepared {
    pub fn prompt(&self) -> &Prompt {
        &self.prompt
    }
}
fn validate(policy: &Policy, app: &AppId, request: &TransferRequest) -> Result<[Account; 2]> {
    for opening in [&request.from, &request.to] {
        if !policy.permitted(app, Scope::Transactions, Some(*opening.account.value())) {
            return Err(Error::Invalid(
                "Transaction permission required for both private accounts",
            ));
        }
    }
    if request.from.account == request.to.account || request.amount == 0 {
        return Err(Error::Invalid(
            "Invalid private transfer amount or accounts",
        ));
    }
    // Reuse asset arithmetic only. No public account read or public action is made.
    let (to, from) = shielded_transfer::expected_outputs(
        &Transfer {
            public_account: request.to.account,
            private_account: request.from.account,
            private_state: request.from.state.clone(),
            identifier: request.from.identifier,
            direction: Direction::Withdrawal,
            amount: request.amount,
        },
        &request.to.state,
        request.asset,
    )?;
    Ok([from, to])
}
pub fn prepare(
    policy: &mut Policy,
    app: &AppId,
    endpoint: &str,
    request: TransferRequest,
    now: u64,
) -> Result<Prepared> {
    let expected = validate(policy, app, &request)?;
    let node = HttpNode::new(endpoint)?;
    let from_commitment = Commitment::new(&request.from.account, &request.from.state);
    let to_commitment = Commitment::new(&request.to.account, &request.to.state);
    let (from_membership, root) = node.commitment_membership(from_commitment)?;
    let (to_membership, to_root) = node.commitment_membership(to_commitment)?;
    if root != to_root {
        return Err(Error::Invalid(
            "Commitment root changed during preparation; prepare again",
        ));
    }
    let mut digest = Sha256::new();
    digest.update(b"logos.wallet.private.pair.v1\0");
    digest.update((endpoint.len() as u64).to_le_bytes());
    digest.update(endpoint.as_bytes());
    digest.update(root);
    for opening in [&request.from, &request.to] {
        digest.update(opening.account.value());
        digest.update(Commitment::new(&opening.account, &opening.state).to_byte_array());
        digest.update(opening.identifier.to_le_bytes());
    }
    digest.update(request.amount.to_le_bytes());
    let (effect, program) = match request.asset {
        Asset::Native => {
            digest.update([0]);
            (
                Effect::NativeTransfer {
                    amount: request.amount.to_string(),
                    destination: *request.to.account.value(),
                },
                programs::authenticated_transfer().id(),
            )
        }
        Asset::Fungible(id) => {
            digest.update([1]);
            digest.update(id.value());
            (
                Effect::TokenTransfer {
                    asset: *id.value(),
                    amount: request.amount.to_string(),
                    destination: *request.to.account.value(),
                },
                programs::token().id(),
            )
        }
        Asset::Nft(id) => {
            digest.update([2]);
            digest.update(id.value());
            (
                Effect::NftTransfer {
                    collection: *id.value(),
                    token: *request.from.account.value(),
                    destination: *request.to.account.value(),
                },
                programs::token().id(),
            )
        }
    };
    let detail = match request.asset {
        Asset::Nft(_) => match token_core::TokenHolding::try_from(&request.from.state.data)
            .map_err(|_| Error::Invalid("Invalid NFT source"))?
        {
            token_core::TokenHolding::NftMaster { print_balance, .. } => format!(
                "The master moves with all {} remaining print rights.",
                print_balance.saturating_sub(1)
            ),
            _ => "One printed copy moves; the reference format has no stable copy serial.".into(),
        },
        _ => String::new(),
    };
    let prompt = policy.request(app, Request::Transaction(Transaction {
        account: *request.from.account.value(), message_hash: digest.finalize().into(), network: endpoint.into(),
        effects: vec![effect, Effect::ContractCall {
            program: logos_registry_sdk::program_bytes(&program), instruction: "transfer between two owned private accounts".into(),
            explanation: format!("Both accounts belong to this wallet and both private states are updated. No public account is changed. Commitments, nullifiers and encrypted outputs are published; this does not guarantee network anonymity. {detail}"),
        }],
    }), now)?;
    Ok(Prepared {
        prompt,
        request,
        memberships: [from_membership, to_membership],
        root,
        expected,
    })
}
/// Returns both checked outputs of one transaction; retain them atomically before broadcast.
pub fn prove(
    policy: &mut Policy,
    app: &AppId,
    prepared: &Prepared,
    endpoint: &str,
    keys: [&PrivateKeyHolder; 2],
    now: u64,
) -> Result<[Proven; 2]> {
    require_local_prover()?;
    let Request::Transaction(request) = &prepared.prompt.request else {
        return Err(Error::Invalid("Expected transaction approval"));
    };
    if request.network != endpoint {
        return Err(Error::Invalid("Endpoint differs from approval"));
    }
    validate(policy, app, &prepared.request)?;
    let openings = [&prepared.request.from, &prepared.request.to];
    for (opening, key) in openings.iter().zip(keys) {
        let account = AccountId::for_private_account(
            &key.generate_nullifier_public_key(),
            &key.generate_viewing_public_key(),
            &PrivateAccountKind::Regular(opening.identifier),
        );
        if account != opening.account {
            return Err(Error::Invalid("Private keys differ from approved accounts"));
        }
    }
    policy.consume(app, prepared.prompt.id, &prepared.prompt.request, now)?;
    let mut states = Vec::new();
    let mut identities = Vec::new();
    for (i, opening) in openings.iter().enumerate() {
        let mut randomness = [0; 33];
        OsRng
            .try_fill_bytes(&mut randomness)
            .map_err(|_| Error::Invalid("Randomness unavailable"))?;
        let mut seed = [0; 32];
        seed.copy_from_slice(&randomness[..32]);
        states.push(AccountWithMetadata {
            account_id: opening.account,
            account: opening.state.clone(),
            is_authorized: true,
        });
        identities.push(InputAccountIdentity::PrivateAuthorizedUpdate {
            vpk: keys[i].generate_viewing_public_key(),
            random_seed: seed,
            view_tag: randomness[32],
            nsk: keys[i].nullifier_secret_key,
            membership_proof: prepared.memberships[i].clone(),
            identifier: opening.identifier,
        });
    }
    let (program, instruction) = match prepared.request.asset {
        Asset::Native => (
            programs::authenticated_transfer(),
            lee::program::Program::serialize_instruction(
                authenticated_transfer_core::Instruction::Transfer {
                    amount: prepared.request.amount,
                },
            ),
        ),
        _ => (
            programs::token(),
            lee::program::Program::serialize_instruction(token_core::Instruction::Transfer {
                amount_to_transfer: prepared.request.amount,
            }),
        ),
    };
    let (output, proof) = circuit::execute_and_prove(
        states,
        instruction.map_err(|e| Error::Prover(e.to_string()))?,
        identities,
        &program.into(),
    )
    .map_err(crate::shielded::circuit_error)?;
    let message = Message::from_circuit_output(vec![], output);
    if !message.public_actions.is_empty() || message.private_actions.len() != 2 {
        return Err(Error::Invalid("Unexpected private pair effects"));
    }
    let mut checked = Vec::new();
    for (i, opening) in openings.iter().enumerate() {
        let pre_commitment = Commitment::new(&opening.account, &opening.state);
        let nullifier =
            Nullifier::for_account_update(&pre_commitment, &keys[i].nullifier_secret_key);
        let mut matching = message
            .private_actions
            .iter()
            .filter(|a| a.nullifier == nullifier);
        let action = matching
            .next()
            .ok_or(Error::Invalid("Missing private account output"))?;
        if matching.next().is_some() || action.root != prepared.root {
            return Err(Error::Invalid(
                "Unexpected private root or duplicate nullifier",
            ));
        }
        let secret = SharedSecretKey::decapsulate(
            &action.encrypted_post_state.epk,
            &keys[i].viewing_secret_key.d,
            &keys[i].viewing_secret_key.z,
        )
        .ok_or(Error::Invalid("Cannot decrypt private output"))?;
        let (kind, state) = EncryptionScheme::decrypt(
            &action.encrypted_post_state.ciphertext,
            &secret,
            &action.nullifier,
        )
        .ok_or(Error::Invalid("Invalid encrypted output"))?;
        let mut expected = prepared.expected[i].clone();
        expected.nonce = expected
            .nonce
            .private_account_nonce_increment(&keys[i].nullifier_secret_key);
        if kind != PrivateAccountKind::Regular(opening.identifier) || state != expected {
            return Err(Error::Invalid("Private pair output differs from approval"));
        }
        checked.push((pre_commitment, state));
    }
    // The circuit independently sorts commitments and nullifier/note pairs.
    // Validate the complete output set, not a position-based association.
    let expected_commitments = openings
        .iter()
        .zip(&checked)
        .map(|(opening, (_, state))| Commitment::new(&opening.account, state));
    if !crate::private_output::exact_commitments(&message.private_actions, expected_commitments) {
        return Err(Error::Invalid(
            "Private pair commitment set differs from approval",
        ));
    }
    let witness = WitnessSet::for_message(&message, proof, &[]);
    let transaction = common::transaction::LeeTransaction::PrivacyPreserving(
        PrivacyPreservingTransaction::new(message, witness),
    )
    .transaction_stateless_check()
    .map_err(|e| Error::Prover(e.to_string()))?;
    let mut checked = checked.into_iter();
    Ok(std::array::from_fn(|i| {
        let (pre_commitment, pending_state) = checked.next().expect("two checked outputs");
        Proven {
            endpoint: endpoint.into(),
            account: openings[i].account,
            pre_commitment,
            transaction: transaction.clone(),
            pending_state,
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use logos_wallet_policy::Grant;
    use std::collections::BTreeSet;

    fn fixture() -> (Policy, AppId, TransferRequest) {
        let from = AccountId::new([11; 32]);
        let to = AccountId::new([12; 32]);
        let app = AppId("private.pair.fixture".into());
        let mut policy = Policy::default();
        policy
            .set_grant(
                app.clone(),
                Grant {
                    accounts: BTreeSet::from([*from.value(), *to.value()]),
                    scopes: BTreeSet::from([Scope::Transactions]),
                },
            )
            .unwrap();
        let state = Account {
            program_owner: programs::authenticated_transfer().id(),
            balance: 10,
            ..Default::default()
        };
        (
            policy,
            app,
            TransferRequest {
                from: Opening {
                    account: from,
                    state: state.clone(),
                    identifier: 4,
                },
                to: Opening {
                    account: to,
                    state,
                    identifier: 5,
                },
                asset: Asset::Native,
                amount: 4,
            },
        )
    }
    #[test]
    fn both_accounts_require_permission_before_any_network_access() {
        let (mut policy, app, request) = fixture();
        policy
            .set_grant(
                app.clone(),
                Grant {
                    accounts: BTreeSet::from([*request.from.account.value()]),
                    scopes: BTreeSet::from([Scope::Transactions]),
                },
            )
            .unwrap();
        assert!(matches!(
            prepare(&mut policy, &app, "not a URL", request, 1),
            Err(Error::Invalid(
                "Transaction permission required for both private accounts"
            ))
        ));
    }
    #[test]
    fn private_native_effects_reject_aliasing_insufficient_funds_and_overflow() {
        let (policy, app, mut request) = fixture();
        let outputs = validate(&policy, &app, &request).unwrap();
        assert_eq!((outputs[0].balance, outputs[1].balance), (6, 14));
        assert_eq!(outputs[0].nonce, request.from.state.nonce);
        request.amount = 11;
        assert!(validate(&policy, &app, &request).is_err());
        request.amount = 4;
        request.to.state.balance = u128::MAX;
        assert!(validate(&policy, &app, &request).is_err());
        request.to.state.balance = 0;
        request.to.account = request.from.account;
        assert!(validate(&policy, &app, &request).is_err());
    }
    #[test]
    fn private_nft_effects_preserve_balances_and_all_master_rights() {
        use token_core::TokenHolding;
        let (policy, app, mut request) = fixture();
        let collection = AccountId::new([13; 32]);
        request.asset = Asset::Nft(collection);
        request.amount = 7;
        request.from.state.program_owner = programs::token().id();
        request.to.state.program_owner = programs::token().id();
        request.from.state.data = (&TokenHolding::NftMaster {
            definition_id: collection,
            print_balance: 7,
        })
            .into();
        request.to.state.data = (&TokenHolding::NftMaster {
            definition_id: collection,
            print_balance: 0,
        })
            .into();
        let outputs = validate(&policy, &app, &request).unwrap();
        assert_eq!((outputs[0].balance, outputs[1].balance), (10, 10));
        assert!(matches!(
            TokenHolding::try_from(&outputs[0].data).unwrap(),
            TokenHolding::NftMaster {
                print_balance: 0,
                ..
            }
        ));
        assert!(matches!(
            TokenHolding::try_from(&outputs[1].data).unwrap(),
            TokenHolding::NftMaster {
                print_balance: 7,
                ..
            }
        ));
        request.amount = 6;
        assert!(validate(&policy, &app, &request).is_err());
        request.amount = 7;
        request.to.state.data = (&TokenHolding::NftMaster {
            definition_id: AccountId::new([14; 32]),
            print_balance: 0,
        })
            .into();
        assert!(validate(&policy, &app, &request).is_err());
    }
}
