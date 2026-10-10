// SPDX-License-Identifier: MIT OR Apache-2.0
//! Native deposits/withdrawals between a public account and an owned private account.
//! Trusted wallet API: private state and keys must never be supplied by a dApp.
use crate::shielded::{Error, Result, require_local_prover};
use common::transaction::LeeTransaction;
use key_protocol::key_management::secret_holders::PrivateKeyHolder;
use lee::{
    Account, AccountId, PrivacyPreservingTransaction, PrivateKey, PublicKey,
    privacy_preserving_transaction::{circuit, message::Message, witness_set::WitnessSet},
};
use lee_core::{
    Commitment, EncryptionScheme, InputAccountIdentity, MembershipProof, Nullifier,
    PrivateAccountKind, SharedSecretKey, account::AccountWithMetadata,
};
use logos_registry_sdk::{AccountReader, HttpNode};
use logos_wallet_policy::{AppId, Effect, Policy, Prompt, Request, Scope, Transaction};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Deposit,
    Withdrawal,
}
pub struct Transfer {
    pub public_account: AccountId,
    pub private_account: AccountId,
    pub private_state: Account,
    pub identifier: u128,
    pub direction: Direction,
    pub amount: u128,
}
#[derive(Clone, Copy)]
pub enum Asset {
    Native,
    Fungible(AccountId),
    Nft(AccountId),
}
impl Asset {
    fn definition(self) -> Option<AccountId> {
        match self {
            Self::Native => None,
            Self::Fungible(id) | Self::Nft(id) => Some(id),
        }
    }
}
pub struct Prepared {
    prompt: Prompt,
    transfer: Transfer,
    public_state: Account,
    membership: MembershipProof,
    root: [u8; 32],
    asset: Asset,
}
impl Prepared {
    pub fn prompt(&self) -> &Prompt {
        &self.prompt
    }
}
pub struct Proven {
    pub(crate) endpoint: String,
    pub(crate) account: AccountId,
    pub(crate) pre_commitment: Commitment,
    pub(crate) transaction: LeeTransaction,
    pub(crate) pending_state: Account,
}
impl Proven {
    pub fn transaction(&self) -> &LeeTransaction {
        &self.transaction
    }
    /// Pending state, never proof of current balance or inclusion.
    pub fn pending_state(&self) -> &Account {
        &self.pending_state
    }
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
    pub fn private_account(&self) -> AccountId {
        self.account
    }
    pub fn pre_commitment(&self) -> Commitment {
        self.pre_commitment
    }
}
pub fn prepare(
    policy: &mut Policy,
    app: &AppId,
    endpoint: &str,
    transfer: Transfer,
    now: u64,
) -> Result<Prepared> {
    prepare_asset(policy, app, endpoint, transfer, Asset::Native, now)
}
/// Fungible transfers between public and owned private holdings of one definition.
pub fn prepare_token(
    policy: &mut Policy,
    app: &AppId,
    endpoint: &str,
    transfer: Transfer,
    definition: AccountId,
    now: u64,
) -> Result<Prepared> {
    prepare_asset(
        policy,
        app,
        endpoint,
        transfer,
        Asset::Fungible(definition),
        now,
    )
}
/// NFT transfer between public and owned private holdings of the same kind.
/// Copies move as one; masters move with all remaining print rights.
pub fn prepare_nft(
    policy: &mut Policy,
    app: &AppId,
    endpoint: &str,
    transfer: Transfer,
    collection: AccountId,
    now: u64,
) -> Result<Prepared> {
    prepare_asset(policy, app, endpoint, transfer, Asset::Nft(collection), now)
}
fn prepare_asset(
    policy: &mut Policy,
    app: &AppId,
    endpoint: &str,
    transfer: Transfer,
    asset: Asset,
    now: u64,
) -> Result<Prepared> {
    let (from, to) = match transfer.direction {
        Direction::Deposit => (transfer.public_account, transfer.private_account),
        Direction::Withdrawal => (transfer.private_account, transfer.public_account),
    };
    if !policy.permitted(app, Scope::Transactions, Some(*from.value())) {
        return Err(Error::Invalid("Transaction permission denied"));
    }
    if transfer.amount == 0 || from == to {
        return Err(Error::Invalid("Invalid transfer amount or accounts"));
    }
    let node = HttpNode::new(endpoint)?;
    let public_state = node.account(transfer.public_account)?;
    expected_outputs(&transfer, &public_state, asset)?;
    let commitment = Commitment::new(&transfer.private_account, &transfer.private_state);
    let (membership, root) = node.commitment_membership(commitment)?;
    let mut hash = Sha256::new();
    hash.update(b"logos.wallet.shielded.transfer.v3\0");
    hash.update([match asset {
        Asset::Native => 0,
        Asset::Fungible(_) => 1,
        Asset::Nft(_) => 2,
    }]);
    if let Some(asset) = asset.definition() {
        hash.update(asset.value());
    }
    hash.update((endpoint.len() as u64).to_le_bytes());
    hash.update(endpoint.as_bytes());
    hash.update(from.value());
    hash.update(to.value());
    hash.update(commitment.to_byte_array());
    hash.update(Commitment::new(&transfer.public_account, &public_state).to_byte_array());
    hash.update(root);
    hash.update(transfer.identifier.to_le_bytes());
    hash.update(transfer.amount.to_le_bytes());
    let explanation = match transfer.direction {
        Direction::Deposit => {
            "Deposit into an owned private account. The public sender and its balance change remain visible on chain."
        }
        Direction::Withdrawal => {
            "Withdraw to a public account. The public recipient and its balance change remain visible on chain."
        }
    };
    let nft_effect = if matches!(asset, Asset::Nft(_)) {
        let source = if transfer.direction == Direction::Deposit {
            &public_state
        } else {
            &transfer.private_state
        };
        match token_core::TokenHolding::try_from(&source.data)
            .map_err(|_| Error::Invalid("Invalid NFT source"))?
        {
            token_core::TokenHolding::NftMaster { print_balance, .. } => format!(
                "Transfer the master and all {} remaining print rights.",
                print_balance.saturating_sub(1)
            ),
            token_core::TokenHolding::NftPrintedCopy { .. } => {
                "Transfer one printed NFT copy. The reference format has no stable copy serial."
                    .into()
            }
            _ => return Err(Error::Invalid("Expected an NFT source")),
        }
    } else {
        String::new()
    };
    let prompt = policy.request(
        app,
        Request::Transaction(Transaction {
            account: *from.value(),
            message_hash: hash.finalize().into(),
            network: endpoint.into(),
            effects: vec![
                match asset {
                    Asset::Nft(collection) => Effect::NftTransfer {collection:*collection.value(),token:*from.value(),destination:*to.value()},
                    Asset::Fungible(asset) => Effect::TokenTransfer {
                        asset: *asset.value(),
                        amount: transfer.amount.to_string(),
                        destination: *to.value(),
                    },
                    Asset::Native => Effect::NativeTransfer {
                        amount: transfer.amount.to_string(),
                        destination: *to.value(),
                    },
                },
                Effect::ContractCall {
                    program: logos_registry_sdk::program_bytes(&if asset.definition().is_some() {
                        programs::token().id()
                    } else {
                        programs::authenticated_transfer().id()
                    }),
                    instruction: "transfer with private account update".into(),
                    explanation: format!(
                        "{explanation} {nft_effect} {}",
                        match asset {
                            Asset::Nft(_) => "The collection and public NFT ownership change remain visible. This is not a private-to-private transfer. A master moves with all its print rights.",
                            Asset::Fungible(_) => "The token definition and public token balance change remain visible.",
                            Asset::Native => "",
                        }
                    ),
                },
            ],
        }),
        now,
    )?;
    Ok(Prepared {
        prompt,
        transfer,
        public_state,
        membership,
        root,
        asset,
    })
}
fn validate_balances(transfer: &Transfer, public: &Account) -> Result<()> {
    let owner = programs::authenticated_transfer().id();
    if public.program_owner != owner || transfer.private_state.program_owner != owner {
        return Err(Error::Invalid(
            "Both accounts must be initialized for native transfers",
        ));
    }
    let (available, destination) = match transfer.direction {
        Direction::Deposit => (public.balance, transfer.private_state.balance),
        Direction::Withdrawal => (transfer.private_state.balance, public.balance),
    };
    if available < transfer.amount || destination.checked_add(transfer.amount).is_none() {
        return Err(Error::Invalid("Insufficient balance or recipient overflow"));
    }
    if transfer.direction == Direction::Deposit && public.nonce.0 == u128::MAX {
        return Err(Error::Invalid("Public sender nonce exhausted"));
    }
    Ok(())
}

pub(crate) fn expected_outputs(
    transfer: &Transfer,
    public: &Account,
    asset: Asset,
) -> Result<(Account, Account)> {
    if let Asset::Nft(collection) = asset {
        return expected_nft_outputs(transfer, public, collection);
    }
    let mut public_after = public.clone();
    let mut private_after = transfer.private_state.clone();
    let (public_balance, private_balance) = if let Some(asset) = asset.definition() {
        let decode = |state: &Account| -> Result<u128> {
            if state.program_owner != programs::token().id() {
                return Err(Error::Invalid(
                    "Both holdings must belong to the pinned token program",
                ));
            }
            match token_core::TokenHolding::try_from(&state.data) {
                Ok(token_core::TokenHolding::Fungible {
                    definition_id,
                    balance,
                }) if definition_id == asset => Ok(balance),
                _ => Err(Error::Invalid(
                    "Fungible holding definition differs from requested asset",
                )),
            }
        };
        (decode(public)?, decode(&transfer.private_state)?)
    } else {
        validate_balances(transfer, public)?;
        (public.balance, transfer.private_state.balance)
    };
    if transfer.amount == 0
        || (transfer.direction == Direction::Deposit && public.nonce.0 == u128::MAX)
    {
        return Err(Error::Invalid(
            "Invalid amount or public sender nonce exhausted",
        ));
    }
    let (public_balance, private_balance) = match transfer.direction {
        Direction::Deposit => (
            public_balance.checked_sub(transfer.amount),
            private_balance.checked_add(transfer.amount),
        ),
        Direction::Withdrawal => (
            public_balance.checked_add(transfer.amount),
            private_balance.checked_sub(transfer.amount),
        ),
    };
    let (Some(public_balance), Some(private_balance)) = (public_balance, private_balance) else {
        return Err(Error::Invalid(
            "Insufficient token balance or recipient overflow",
        ));
    };
    if let Some(definition_id) = asset.definition() {
        public_after.data = (&token_core::TokenHolding::Fungible {
            definition_id,
            balance: public_balance,
        })
            .into();
        private_after.data = (&token_core::TokenHolding::Fungible {
            definition_id,
            balance: private_balance,
        })
            .into();
    } else {
        public_after.balance = public_balance;
        private_after.balance = private_balance;
    }
    Ok((public_after, private_after))
}

fn expected_nft_outputs(
    transfer: &Transfer,
    public: &Account,
    collection: AccountId,
) -> Result<(Account, Account)> {
    use token_core::TokenHolding;
    if transfer.amount == 0
        || (transfer.direction == Direction::Deposit && public.nonce.0 == u128::MAX)
    {
        return Err(Error::Invalid(
            "Invalid NFT amount or public nonce exhausted",
        ));
    }
    let decode = |state: &Account| -> Result<TokenHolding> {
        if state.program_owner != programs::token().id() {
            return Err(Error::Invalid("NFT holding has wrong program owner"));
        }
        let holding = TokenHolding::try_from(&state.data)
            .map_err(|_| Error::Invalid("Invalid NFT holding data"))?;
        if holding.definition_id() != collection {
            return Err(Error::Invalid(
                "NFT collection differs from requested collection",
            ));
        }
        Ok(holding)
    };
    let mut public_holding = decode(public)?;
    let mut private_holding = decode(&transfer.private_state)?;
    let (source, destination) = match transfer.direction {
        Direction::Deposit => (&mut public_holding, &mut private_holding),
        Direction::Withdrawal => (&mut private_holding, &mut public_holding),
    };
    match (source, destination) {
        (
            TokenHolding::NftPrintedCopy { owned: from, .. },
            TokenHolding::NftPrintedCopy { owned: to, .. },
        ) if *from && !*to && transfer.amount == 1 => {
            *from = false;
            *to = true;
        }
        (
            TokenHolding::NftMaster {
                print_balance: from,
                ..
            },
            TokenHolding::NftMaster {
                print_balance: to, ..
            },
        ) if *from > 0 && *to == 0 && transfer.amount == *from => {
            std::mem::swap(from, to);
        }
        _ => {
            return Err(Error::Invalid(
                "NFT source is empty, recipient occupied, kinds differ, or amount would split master rights",
            ));
        }
    }
    let mut public_after = public.clone();
    let mut private_after = transfer.private_state.clone();
    public_after.data = (&public_holding).into();
    private_after.data = (&private_holding).into();
    Ok((public_after, private_after))
}

/// Local proving only. Approval is consumed before proving; no network submission occurs.
pub fn prove(
    policy: &mut Policy,
    app: &AppId,
    prepared: &Prepared,
    endpoint: &str,
    keys: &PrivateKeyHolder,
    public_signer: Option<&PrivateKey>,
    now: u64,
) -> Result<Proven> {
    require_local_prover()?;
    let transfer = &prepared.transfer;
    let kind = PrivateAccountKind::Regular(transfer.identifier);
    let vpk = keys.generate_viewing_public_key();
    let account =
        AccountId::for_private_account(&keys.generate_nullifier_public_key(), &vpk, &kind);
    let Request::Transaction(request) = &prepared.prompt.request else {
        return Err(Error::Invalid("Expected transaction approval"));
    };
    if account != transfer.private_account || request.network != endpoint {
        return Err(Error::Invalid(
            "Private key or endpoint differs from approval",
        ));
    }
    let signers = match (transfer.direction, public_signer) {
        (Direction::Deposit, Some(key))
            if AccountId::from(&PublicKey::new_from_private_key(key))
                == transfer.public_account =>
        {
            vec![key]
        }
        (Direction::Withdrawal, None) => vec![],
        _ => {
            return Err(Error::Invalid(
                "Public signer differs from approved direction/account",
            ));
        }
    };
    policy.consume(app, prepared.prompt.id, &prepared.prompt.request, now)?;
    let mut seed = [0; 32];
    OsRng
        .try_fill_bytes(&mut seed)
        .map_err(|_| Error::Invalid("Randomness unavailable"))?;
    let mut tag = [0; 1];
    OsRng
        .try_fill_bytes(&mut tag)
        .map_err(|_| Error::Invalid("Randomness unavailable"))?;
    let public = AccountWithMetadata {
        account_id: transfer.public_account,
        account: prepared.public_state.clone(),
        is_authorized: transfer.direction == Direction::Deposit,
    };
    let private = AccountWithMetadata {
        account_id: account,
        account: transfer.private_state.clone(),
        is_authorized: true,
    };
    let private_identity = InputAccountIdentity::PrivateAuthorizedUpdate {
        vpk,
        random_seed: seed,
        view_tag: tag[0],
        nsk: keys.nullifier_secret_key,
        membership_proof: prepared.membership.clone(),
        identifier: transfer.identifier,
    };
    let (states, identities, nonces) = match transfer.direction {
        Direction::Deposit => (
            vec![public, private],
            vec![InputAccountIdentity::Public, private_identity],
            vec![prepared.public_state.nonce],
        ),
        Direction::Withdrawal => (
            vec![private, public],
            vec![private_identity, InputAccountIdentity::Public],
            vec![],
        ),
    };
    let program = if prepared.asset.definition().is_some() {
        programs::token()
    } else {
        programs::authenticated_transfer()
    };
    let instruction = if prepared.asset.definition().is_some() {
        lee::program::Program::serialize_instruction(token_core::Instruction::Transfer {
            amount_to_transfer: transfer.amount,
        })
    } else {
        lee::program::Program::serialize_instruction(
            authenticated_transfer_core::Instruction::Transfer {
                amount: transfer.amount,
            },
        )
    }
    .map_err(|e| Error::Prover(e.to_string()))?;
    let (output, proof) =
        circuit::execute_and_prove(states, instruction, identities, &program.into())
            .map_err(crate::shielded::circuit_error)?;
    let message = Message::from_circuit_output(nonces, output);
    if message.public_actions.len() != 1 || message.private_actions.len() != 1 {
        return Err(Error::Invalid("Unexpected shielded transfer effects"));
    }
    let (expected_public, mut expected_private) =
        expected_outputs(transfer, &prepared.public_state, prepared.asset)?;
    expected_private.nonce = expected_private
        .nonce
        .private_account_nonce_increment(&keys.nullifier_secret_key);
    let public_action = &message.public_actions[0];
    if public_action.account_id != transfer.public_account
        || public_action.post_state != expected_public
    {
        return Err(Error::Invalid("Unexpected public transfer output"));
    }
    let pre_commitment = Commitment::new(&account, &transfer.private_state);
    let action = &message.private_actions[0];
    if action.root != prepared.root
        || action.nullifier
            != Nullifier::for_account_update(&pre_commitment, &keys.nullifier_secret_key)
    {
        return Err(Error::Invalid("Unexpected private transfer root/nullifier"));
    }
    let secret = SharedSecretKey::decapsulate(
        &action.encrypted_post_state.epk,
        &keys.viewing_secret_key.d,
        &keys.viewing_secret_key.z,
    )
    .ok_or(Error::Invalid("Cannot decrypt private transfer result"))?;
    let (actual_kind, state) = EncryptionScheme::decrypt(
        &action.encrypted_post_state.ciphertext,
        &secret,
        &action.nullifier,
    )
    .ok_or(Error::Invalid("Invalid encrypted transfer result"))?;
    if actual_kind != kind
        || state != expected_private
        || Commitment::new(&account, &state) != action.commitment
    {
        return Err(Error::Invalid(
            "Private transfer commitment/effects mismatch",
        ));
    }
    let witness = WitnessSet::for_message(&message, proof, &signers);
    let transaction =
        LeeTransaction::PrivacyPreserving(PrivacyPreservingTransaction::new(message, witness))
            .transaction_stateless_check()
            .map_err(|e| Error::Prover(e.to_string()))?;
    Ok(Proven {
        endpoint: endpoint.into(),
        account,
        pre_commitment,
        transaction,
        pending_state: state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn balance_and_nonce_validation_covers_both_directions() {
        let mut public = Account {
            program_owner: programs::authenticated_transfer().id(),
            balance: 10,
            ..Default::default()
        };
        let mut transfer = Transfer {
            public_account: AccountId::new([1; 32]),
            private_account: AccountId::new([2; 32]),
            private_state: public.clone(),
            identifier: 0,
            direction: Direction::Deposit,
            amount: 11,
        };
        assert!(validate_balances(&transfer, &public).is_err());
        transfer.amount = 10;
        assert!(validate_balances(&transfer, &public).is_ok());
        public.nonce.0 = u128::MAX;
        assert!(validate_balances(&transfer, &public).is_err());
        public.nonce.0 = 0;
        transfer.private_state.balance = u128::MAX;
        assert!(validate_balances(&transfer, &public).is_err());
        transfer.direction = Direction::Withdrawal;
        transfer.private_state.balance = 10;
        public.balance = u128::MAX;
        assert!(validate_balances(&transfer, &public).is_err());
        public.balance = 10;
        assert!(validate_balances(&transfer, &public).is_ok());
        public.program_owner = [0; 8];
        assert!(validate_balances(&transfer, &public).is_err());
    }
    #[test]
    fn token_effects_preserve_native_state_and_reject_wrong_assets() {
        let asset = AccountId::new([7; 32]);
        let holding = |balance| Account {
            program_owner: programs::token().id(),
            balance: 9,
            data: (&token_core::TokenHolding::Fungible {
                definition_id: asset,
                balance,
            })
                .into(),
            ..Default::default()
        };
        let public = holding(20);
        let mut transfer = Transfer {
            public_account: AccountId::new([1; 32]),
            private_account: AccountId::new([2; 32]),
            private_state: holding(0),
            identifier: 0,
            direction: Direction::Deposit,
            amount: 5,
        };
        let (after_public, after_private) =
            expected_outputs(&transfer, &public, Asset::Fungible(asset)).unwrap();
        assert_eq!(after_public, holding(15));
        assert_eq!(after_private, holding(5));
        assert!(
            expected_outputs(&transfer, &public, Asset::Fungible(AccountId::new([8; 32]))).is_err()
        );
        assert!(expected_outputs(&transfer, &public, Asset::Native).is_err());
        transfer.amount = 21;
        assert!(expected_outputs(&transfer, &public, Asset::Fungible(asset)).is_err());
        transfer.amount = 5;
        transfer.private_state = holding(u128::MAX);
        assert!(expected_outputs(&transfer, &public, Asset::Fungible(asset)).is_err());
        transfer.direction = Direction::Withdrawal;
        transfer.private_state = holding(5);
        let (after_public, after_private) =
            expected_outputs(&transfer, &public, Asset::Fungible(asset)).unwrap();
        assert_eq!(after_public, holding(25));
        assert_eq!(after_private, holding(0));
        transfer.private_state.data = (&token_core::TokenHolding::NftPrintedCopy {
            definition_id: asset,
            owned: true,
        })
            .into();
        assert!(expected_outputs(&transfer, &public, Asset::Fungible(asset)).is_err());
    }
    #[test]
    fn nft_outputs_preserve_native_state_and_cannot_split_master_rights() {
        use token_core::TokenHolding;
        let collection = AccountId::new([8; 32]);
        let state = |holding: TokenHolding| Account {
            program_owner: programs::token().id(),
            balance: 9,
            data: (&holding).into(),
            ..Default::default()
        };
        let copy = |owned| {
            state(TokenHolding::NftPrintedCopy {
                definition_id: collection,
                owned,
            })
        };
        let master = |print_balance| {
            state(TokenHolding::NftMaster {
                definition_id: collection,
                print_balance,
            })
        };
        let mut transfer = Transfer {
            public_account: AccountId::new([1; 32]),
            private_account: AccountId::new([2; 32]),
            private_state: copy(false),
            identifier: 0,
            direction: Direction::Deposit,
            amount: 1,
        };
        let (public_after, private_after) =
            expected_outputs(&transfer, &copy(true), Asset::Nft(collection)).unwrap();
        assert_eq!(public_after, copy(false));
        assert_eq!(private_after, copy(true));
        transfer.private_state = private_after;
        transfer.direction = Direction::Withdrawal;
        assert_eq!(
            expected_outputs(&transfer, &public_after, Asset::Nft(collection)).unwrap(),
            (copy(true), copy(false))
        );
        assert!(expected_outputs(&transfer, &copy(true), Asset::Nft(collection)).is_err());
        transfer.amount = 2;
        assert!(expected_outputs(&transfer, &copy(false), Asset::Nft(collection)).is_err());
        transfer.direction = Direction::Deposit;
        transfer.private_state = master(0);
        transfer.amount = 4;
        assert_eq!(
            expected_outputs(&transfer, &master(4), Asset::Nft(collection)).unwrap(),
            (master(0), master(4))
        );
        transfer.amount = 3;
        assert!(expected_outputs(&transfer, &master(4), Asset::Nft(collection)).is_err());
        transfer.amount = 4;
        transfer.private_state = master(1);
        assert!(expected_outputs(&transfer, &master(4), Asset::Nft(collection)).is_err());
        transfer.private_state = copy(false);
        assert!(expected_outputs(&transfer, &master(4), Asset::Nft(collection)).is_err());
        transfer.amount = 1;
        assert!(
            expected_outputs(&transfer, &copy(true), Asset::Nft(AccountId::new([9; 32]))).is_err()
        );
        let mut wrong = copy(true);
        wrong.program_owner = [0; 8];
        assert!(expected_outputs(&transfer, &wrong, Asset::Nft(collection)).is_err());
        let mut exhausted = copy(true);
        exhausted.nonce.0 = u128::MAX;
        assert!(expected_outputs(&transfer, &exhausted, Asset::Nft(collection)).is_err());
    }
    #[test]
    fn missing_permission_is_rejected_before_rpc() {
        let transfer = Transfer {
            public_account: AccountId::new([1; 32]),
            private_account: AccountId::new([2; 32]),
            private_state: Account::default(),
            identifier: 0,
            direction: Direction::Withdrawal,
            amount: 1,
        };
        assert!(matches!(
            prepare(
                &mut Policy::default(),
                &AppId("untrusted".into()),
                "http://127.0.0.1:1",
                transfer,
                0
            ),
            Err(Error::Invalid("Transaction permission denied"))
        ));
    }
}
