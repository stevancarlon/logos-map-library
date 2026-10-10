// SPDX-License-Identifier: MIT OR Apache-2.0
//! Genuine LEZ shielded initialization. Witnesses stay in the explicitly selected
//! local r0vm process. No development receipts or hosted prover are accepted.
use common::transaction::LeeTransaction;
use key_protocol::key_management::secret_holders::PrivateKeyHolder;
use lee::{
    Account, AccountId, PrivacyPreservingTransaction,
    privacy_preserving_transaction::{circuit, message::Message, witness_set::WitnessSet},
};
use lee_core::{
    Commitment, EncryptionScheme, InputAccountIdentity, Nullifier, PrivateAccountKind,
    SharedSecretKey, account::AccountWithMetadata,
};
use logos_registry_sdk::{AccountReader, HttpNode};
use logos_wallet_policy::{AppId, Effect, Policy, Prompt, Request, Scope, Transaction};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Node(#[from] logos_registry_sdk::Error),
    #[error(transparent)]
    Policy(#[from] logos_wallet_policy::Error),
    #[error("{0}")]
    Invalid(&'static str),
    #[error("Local shielded prover failed: {0}")]
    Prover(String),
}
pub type Result<T> = std::result::Result<T, Error>;
/// Preserve the local prover's failure reason: upstream Display omits this payload.
pub(crate) fn circuit_error(error: lee::error::LeeError) -> Error {
    match error {
        lee::error::LeeError::CircuitProvingError(reason) => {
            Error::Prover(format!("Circuit proving error: {reason}"))
        }
        other => Error::Prover(other.to_string()),
    }
}

pub struct PreparedInitialization {
    prompt: Prompt,
    account: AccountId,
    identifier: u128,
    root: [u8; 32],
    token_definition: Option<(AccountId, Account)>,
}
impl PreparedInitialization {
    pub fn prompt(&self) -> &Prompt {
        &self.prompt
    }
}
pub struct ProvenInitialization {
    pub(crate) endpoint: String,
    pub(crate) account: AccountId,
    pub(crate) transaction: LeeTransaction,
    /// Decrypted output is local pending state, never confirmed merely by proving.
    pub(crate) pending_state: Account,
}
impl ProvenInitialization {
    pub fn transaction(&self) -> &LeeTransaction {
        &self.transaction
    }
    /// Trusted wallet only. This state is pending until the exact transaction is included.
    pub fn pending_state(&self) -> &Account {
        &self.pending_state
    }
}
pub fn prepare_initialize(
    policy: &mut Policy,
    app: &AppId,
    endpoint: &str,
    keys: &PrivateKeyHolder,
    identifier: u128,
    root: [u8; 32],
    now: u64,
) -> Result<PreparedInitialization> {
    let account = AccountId::for_private_account(
        &keys.generate_nullifier_public_key(),
        &keys.generate_viewing_public_key(),
        &PrivateAccountKind::Regular(identifier),
    );
    let program = programs::authenticated_transfer().id();
    let mut hash = Sha256::new();
    hash.update(b"logos.wallet.shielded.initialize.v1\0");
    hash.update((endpoint.len() as u64).to_le_bytes());
    hash.update(endpoint.as_bytes());
    hash.update(account.value());
    hash.update(root);
    hash.update(identifier.to_le_bytes());
    let prompt = policy.request(
        app,
        Request::Transaction(Transaction {
            account: *account.value(),
            message_hash: hash.finalize().into(),
            effects: vec![Effect::InitializeNativeAccount {
                program: logos_registry_sdk::program_bytes(&program),
            }],
            network: endpoint.into(),
        }),
        now,
    )?;
    Ok(PreparedInitialization {
        prompt,
        account,
        identifier,
        root,
        token_definition: None,
    })
}
/// Initialize an owned private token holding. The public definition remains visible.
pub fn prepare_token_initialize(
    policy: &mut Policy,
    app: &AppId,
    endpoint: &str,
    keys: &PrivateKeyHolder,
    identifier: u128,
    definition: AccountId,
    now: u64,
) -> Result<PreparedInitialization> {
    let account = AccountId::for_private_account(
        &keys.generate_nullifier_public_key(),
        &keys.generate_viewing_public_key(),
        &PrivateAccountKind::Regular(identifier),
    );
    if !policy.permitted(app, Scope::Transactions, Some(*account.value())) {
        return Err(Error::Invalid("Transaction permission denied"));
    }
    let node = HttpNode::new(endpoint)?;
    let state = node.account(definition)?;
    if definition == account || state.program_owner != programs::token().id() {
        return Err(Error::Invalid("Invalid token definition account or owner"));
    }
    token_core::TokenDefinition::try_from(&state.data)
        .map_err(|_| Error::Invalid("Invalid token definition data"))?;
    let root = node.commitment_root()?;
    let mut hash = Sha256::new();
    hash.update(b"logos.wallet.shielded.token.initialize.v1\0");
    hash.update((endpoint.len() as u64).to_le_bytes());
    hash.update(endpoint.as_bytes());
    hash.update(account.value());
    hash.update(definition.value());
    hash.update(Commitment::new(&definition, &state).to_byte_array());
    hash.update(root);
    hash.update(identifier.to_le_bytes());
    let prompt = policy.request(app, Request::Transaction(Transaction {
        account: *account.value(), message_hash: hash.finalize().into(), network: endpoint.into(),
        effects: vec![Effect::ContractCall {
            program: logos_registry_sdk::program_bytes(&programs::token().id()),
            instruction: "InitializeAccount".into(),
            explanation: format!("Initialize an empty private token holding. Public definition {definition} remains visible; no tokens are minted or transferred."),
        }],
    }), now)?;
    Ok(PreparedInitialization {
        prompt,
        account,
        identifier,
        root,
        token_definition: Some((definition, state)),
    })
}
fn check_configuration(prover: Option<&str>, development: Option<&str>) -> Result<()> {
    if prover != Some("ipc") {
        return Err(Error::Invalid(
            "Set RISC0_PROVER=ipc to keep private witnesses in the local prover",
        ));
    }
    if development.is_some_and(|value| value != "0") {
        return Err(Error::Invalid(
            "Development proofs are forbidden for shielded wallet operations",
        ));
    }
    Ok(())
}
pub fn require_local_prover() -> Result<()> {
    check_configuration(
        std::env::var("RISC0_PROVER").ok().as_deref(),
        std::env::var("RISC0_DEV_MODE").ok().as_deref(),
    )?;
    let server = std::env::var_os("RISC0_SERVER_PATH")
        .ok_or(Error::Invalid("Set the local RISC0_SERVER_PATH"))?;
    let server = std::path::Path::new(&server);
    if !server.is_absolute() || !server.is_file() {
        return Err(Error::Invalid("Local prover executable is missing"));
    }
    Ok(())
}
/// Consumes explicit approval before expensive proving. Nothing is submitted here.
/// The caller must retain the signed hash and confirm inclusion before committing state.
pub fn prove_initialize(
    policy: &mut Policy,
    app: &AppId,
    prepared: &PreparedInitialization,
    endpoint: &str,
    keys: &PrivateKeyHolder,
    now: u64,
) -> Result<ProvenInitialization> {
    require_local_prover()?;
    let kind = PrivateAccountKind::Regular(prepared.identifier);
    let vpk = keys.generate_viewing_public_key();
    let account =
        AccountId::for_private_account(&keys.generate_nullifier_public_key(), &vpk, &kind);
    let Request::Transaction(request) = &prepared.prompt.request else {
        return Err(Error::Invalid("Expected transaction approval"));
    };
    if account != prepared.account || request.network != endpoint {
        return Err(Error::Invalid(
            "Private key or endpoint differs from the approved operation",
        ));
    }
    policy.consume(app, prepared.prompt.id, &prepared.prompt.request, now)?;
    let mut random_seed = [0; 32];
    OsRng
        .try_fill_bytes(&mut random_seed)
        .map_err(|_| Error::Invalid("Randomness unavailable"))?;
    let program = if prepared.token_definition.is_some() {
        programs::token()
    } else {
        programs::authenticated_transfer()
    };
    let instruction = if prepared.token_definition.is_some() {
        lee::program::Program::serialize_instruction(token_core::Instruction::InitializeAccount)
    } else {
        lee::program::Program::serialize_instruction(
            authenticated_transfer_core::Instruction::Initialize,
        )
    }
    .map_err(|e| Error::Prover(e.to_string()))?;
    let mut states = vec![AccountWithMetadata {
        account_id: account,
        account: Account::default(),
        is_authorized: true,
    }];
    let mut identities = vec![InputAccountIdentity::PrivateAuthorizedInit {
        vpk,
        random_seed,
        nsk: keys.nullifier_secret_key,
        identifier: prepared.identifier,
        commitment_root: prepared.root,
    }];
    let mut expected = Account {
        program_owner: program.id(),
        nonce: lee_core::account::Nonce::private_account_nonce_init(&account),
        ..Default::default()
    };
    if let Some((definition, state)) = &prepared.token_definition {
        let parsed = token_core::TokenDefinition::try_from(&state.data)
            .map_err(|_| Error::Invalid("Invalid token definition data"))?;
        expected.data =
            (&token_core::TokenHolding::zeroized_from_definition(*definition, &parsed)).into();
        states.insert(
            0,
            AccountWithMetadata {
                account_id: *definition,
                account: state.clone(),
                is_authorized: false,
            },
        );
        identities.insert(0, InputAccountIdentity::Public);
    }
    let (output, proof) =
        circuit::execute_and_prove(states, instruction, identities, &program.into())
            .map_err(circuit_error)?;
    let message = Message::from_circuit_output(vec![], output);
    let public_valid = match &prepared.token_definition {
        None => message.public_actions.is_empty(),
        Some((definition, state)) => {
            message.public_actions.len() == 1
                && message.public_actions[0].account_id == *definition
                && message.public_actions[0].post_state == *state
        }
    };
    if !public_valid || message.private_actions.len() != 1 {
        return Err(Error::Invalid("Unexpected shielded initialization effects"));
    }
    let action = &message.private_actions[0];
    if action.root != prepared.root
        || action.nullifier != Nullifier::for_account_initialization(&account)
    {
        return Err(Error::Invalid("Unexpected initialization nullifier"));
    }
    let secret = SharedSecretKey::decapsulate(
        &action.encrypted_post_state.epk,
        &keys.viewing_secret_key.d,
        &keys.viewing_secret_key.z,
    )
    .ok_or(Error::Invalid(
        "Cannot decrypt private initialization result",
    ))?;
    let (actual_kind, state) = EncryptionScheme::decrypt(
        &action.encrypted_post_state.ciphertext,
        &secret,
        &action.nullifier,
    )
    .ok_or(Error::Invalid("Invalid encrypted initialization result"))?;
    if actual_kind != kind
        || Commitment::new(&account, &state) != action.commitment
        || state != expected
    {
        return Err(Error::Invalid(
            "Private initialization commitment/effects mismatch",
        ));
    }
    let witness = WitnessSet::for_message(&message, proof, &[]);
    let transaction =
        LeeTransaction::PrivacyPreserving(PrivacyPreservingTransaction::new(message, witness));
    let transaction = transaction
        .transaction_stateless_check()
        .map_err(|e| Error::Prover(e.to_string()))?;
    Ok(ProvenInitialization {
        endpoint: endpoint.to_owned(),
        account,
        transaction,
        pending_state: state,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configuration_rejects_remote_and_fake_provers() {
        assert!(check_configuration(Some("ipc"), Some("0")).is_ok());
        for prover in [None, Some("bonsai"), Some("actor")] {
            assert!(check_configuration(prover, None).is_err());
        }
        for dev in ["1", "true", ""] {
            assert!(check_configuration(Some("ipc"), Some(dev)).is_err());
        }
    }
}
