// SPDX-License-Identifier: MIT OR Apache-2.0
//! v0.3-only private identities and quiet, bounded note decoding. No legacy migration.
use crate::{AccountId, Error, Node, Result};
use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};
use hmac::{Hmac, Mac};
use lee_core_v03::{
    AuthorizationSecretKey, NullifierPublicKey, NullifierSecretKey, encryption::ViewingPublicKey,
};
use lee_core_v03::{
    Commitment, Identifier, MembershipProof, Nullifier, PrivateAccountKind, SharedSecretKey,
    account::Account, encryption::Ciphertext,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// Owned serialization is only suitable for the encrypted wallet payload.
/// Debug intentionally excludes spending and viewing material.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateIdentity {
    seed: [u8; 32],
    identifier: [u8; 32],
}
impl Drop for PrivateIdentity {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.identifier.zeroize();
    }
}
impl PrivateIdentity {
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0; 32]);
        let mut identifier = Zeroizing::new([0; 32]);
        OsRng
            .try_fill_bytes(seed.as_mut())
            .map_err(|_| Error::Invalid("OS randomness unavailable"))?;
        OsRng
            .try_fill_bytes(identifier.as_mut())
            .map_err(|_| Error::Invalid("OS randomness unavailable"))?;
        Ok(Self {
            seed: *seed,
            identifier: *identifier,
        })
    }
    /// Explicit owner import of a v0.3 spending seed and opaque 256-bit identifier.
    pub fn from_seed(seed: Zeroizing<[u8; 32]>, identifier: [u8; 32]) -> Self {
        Self {
            seed: *seed,
            identifier,
        }
    }
    pub fn account(&self) -> AccountId {
        self.with_keys(|keys| {
            AccountId::from_bytes(
                *lee_v03::AccountId::for_regular_private_account(
                    &keys.generate_nullifier_public_key(),
                    &keys.generate_viewing_public_key(),
                    Identifier::new(self.identifier),
                )
                .value(),
            )
        })
    }
    pub fn identifier(&self) -> Identifier {
        Identifier::new(self.identifier)
    }
    pub(crate) fn with_keys<T>(&self, operation: impl FnOnce(&PrivateKeys) -> T) -> T {
        // Exact pinned key_protocol SecretSpendingKey index-zero derivation.
        // Keeping this small primitive here avoids pulling an unrelated blockchain
        // node/circuit dependency graph into the wallet's key holder.
        let mut hash = Sha256::new();
        hash.update(b"/LEE-Keys/v1/Authorization/Secret");
        hash.update(self.seed);
        hash.update(0u32.to_be_bytes());
        let ask = AuthorizationSecretKey(hash.finalize().into());
        let mut mac = <Hmac<sha2::Sha512> as Mac>::new_from_slice(b"/LEE-Keys/v1/Viewing/Seed")
            .expect("HMAC accepts this key length");
        mac.update(b"/LEE-Keys/v1/Viewing/Secret");
        mac.update(&self.seed);
        mac.update(&0u32.to_be_bytes());
        let seed = Zeroizing::new(<[u8; 64]>::from(mac.finalize().into_bytes()));
        let keys = PrivateKeys {
            authorization_secret_key: ask,
            d: seed[..32].try_into().expect("32 bytes"),
            z: seed[32..].try_into().expect("32 bytes"),
        };
        operation(&keys)
    }
}

pub(crate) struct PrivateKeys {
    authorization_secret_key: AuthorizationSecretKey,
    d: [u8; 32],
    z: [u8; 32],
}
impl Drop for PrivateKeys {
    fn drop(&mut self) {
        self.authorization_secret_key.0.zeroize();
        self.d.zeroize();
        self.z.zeroize();
    }
}
impl PrivateKeys {
    fn nullifier_secret_key(&self) -> NullifierSecretKey {
        NullifierSecretKey::from(&self.authorization_secret_key)
    }
    fn generate_nullifier_public_key(&self) -> NullifierPublicKey {
        NullifierPublicKey::from(&self.nullifier_secret_key())
    }
    fn generate_viewing_public_key(&self) -> ViewingPublicKey {
        ViewingPublicKey::from_seed(&self.d, &self.z)
    }
}

/// Same pinned ChaCha20/KDF wire format, without upstream's secret-bearing error
/// logging. Bound input and use zeroizing owned plaintext and key buffers.
/// Successful parsing is not authentication: callers must check the commitment.
fn decrypt_quiet(
    ciphertext: &Ciphertext,
    secret: &SharedSecretKey,
    nullifier: &Nullifier,
) -> Result<(PrivateAccountKind, Account)> {
    let bytes = ciphertext.as_bytes();
    if bytes.len() < PrivateAccountKind::HEADER_LEN || bytes.len() > 128 * 1024 {
        return Err(Error::Invalid("invalid private note length"));
    }
    let mut hash = Sha256::new();
    hash.update(b"LEE/v0.3/KDF-SHA256/");
    hash.update(secret.0);
    hash.update(nullifier.to_byte_array());
    let key = Zeroizing::new(<[u8; 32]>::from(hash.finalize()));
    let mut plaintext = Zeroizing::new(bytes.to_vec());
    let mut cipher = ChaCha20::new((&*key).into(), (&[0; 12]).into());
    cipher.apply_keystream(&mut plaintext);
    let header = plaintext[..PrivateAccountKind::HEADER_LEN]
        .try_into()
        .map_err(|_| Error::Invalid("invalid private note"))?;
    let kind = PrivateAccountKind::from_header_bytes(header)
        .ok_or(Error::Invalid("invalid private note"))?;
    let mut input = &plaintext[PrivateAccountKind::HEADER_LEN..];
    let nonce = u128::from_le_bytes(take(&mut input, 16)?.try_into().expect("16 bytes"));
    let count = u32::from_le_bytes(take(&mut input, 4)?.try_into().expect("4 bytes"));
    if count > 256 {
        return Err(Error::Invalid("too many private account shards"));
    }
    let mut shards = std::collections::BTreeMap::new();
    let mut previous = None;
    for _ in 0..count {
        let id = lee_v03::AccountId::new(take(&mut input, 32)?.try_into().expect("32 bytes"));
        let length = u32::from_le_bytes(take(&mut input, 4)?.try_into().expect("4 bytes")) as usize;
        if length > crate::MAX_SHARD_BYTES || previous.is_some_and(|p| p >= id) {
            return Err(Error::Invalid("invalid private shard encoding"));
        }
        let data = take(&mut input, length)?
            .to_vec()
            .try_into()
            .map_err(|_| Error::Invalid("oversized private shard"))?;
        shards.insert(id, data);
        previous = Some(id);
    }
    if input.iter().any(|b| *b != 0) {
        return Err(Error::Invalid("invalid private note padding"));
    }
    Ok((
        kind,
        Account {
            nonce: nonce.into(),
            data: lee_core_v03::account::AccountData { shards },
        },
    ))
}

fn take<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8]> {
    if count > input.len() {
        return Err(Error::Invalid("truncated private note"));
    }
    let (head, tail) = input.split_at(count);
    *input = tail;
    Ok(head)
}

pub trait PrivateReader {
    fn proofs_and_root(
        &self,
        commitments: &[Commitment],
    ) -> Result<(Vec<Option<MembershipProof>>, [u8; 32])>;
}
impl PrivateReader for Node {
    fn proofs_and_root(
        &self,
        commitments: &[Commitment],
    ) -> Result<(Vec<Option<MembershipProof>>, [u8; 32])> {
        if commitments.len() > 32 {
            return Err(Error::Invalid("too many commitment lookups"));
        }
        let result: (Vec<Option<MembershipProof>>, [u8; 32]) =
            self.read("getProofsAndRoot", json!([commitments]))?;
        validate_memberships(commitments, &result.0, result.1)?;
        Ok(result)
    }
}
pub fn validate_memberships(
    commitments: &[Commitment],
    proofs: &[Option<MembershipProof>],
    root: [u8; 32],
) -> Result<()> {
    if commitments.len() > 32 || proofs.len() != commitments.len() {
        return Err(Error::Invalid("commitment proof count mismatch"));
    }
    for (commitment, proof) in commitments.iter().zip(proofs) {
        if let Some(proof) = proof {
            let depth = proof.1.len();
            if depth > 64
                || (depth < usize::BITS as usize && proof.0 >> depth != 0)
                || lee_core_v03::compute_digest_for_path(commitment, proof) != root
            {
                return Err(Error::Invalid(
                    "commitment proof does not match requested state",
                ));
            }
        }
    }
    Ok(())
}

use crate::transfer::NativeReader;
use lee_core_v03::{
    DummyInput, EncryptedAccountData, NullifierWitness, PrivacyPreservingCircuitOutput,
    PrivateWitness, WitnessKind,
    account::{Nonce, ProgramShardSelector},
    native_token,
};
use lee_v03::{
    PrivacyPreservingTransaction, PrivateKey, PublicKey,
    privacy_preserving_transaction::{
        circuit::{self, ProgramWithDependencies},
        message::Message,
        witness_set::WitnessSet,
    },
};
use logos_wallet_policy::{AppId, Effect, Policy, Prompt, Request, Scope, Transaction};
use std::collections::BTreeSet;

pub trait ShieldedReader: PrivateReader + NativeReader {
    fn endpoint(&self) -> &str;
    fn verify_privacy_circuit(&self) -> Result<()>;
}
impl ShieldedReader for Node {
    fn endpoint(&self) -> &str {
        &self.endpoint
    }
    fn verify_privacy_circuit(&self) -> Result<()> {
        if self.program_ids()?.get("privacy_preserving_circuit")
            != Some(&lee_v03::PRIVACY_PRESERVING_CIRCUIT_ID)
        {
            return Err(Error::Invalid(
                "privacy circuit differs from pinned v0.3 program",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Deposit,
    Withdrawal,
}
#[derive(Clone, Copy)]
pub struct NativeOperation {
    pub public_account: AccountId,
    pub direction: Direction,
    pub amount: u128,
}
pub struct Prepared {
    prompt: Prompt,
    endpoint: String,
    operation: NativeOperation,
    private_account: AccountId,
    before: Option<Account>,
    after: Account,
    public_nonce: u128,
    public_balance: u128,
    membership: Option<MembershipProof>,
    root: [u8; 32],
    nullifier: Nullifier,
}
impl Prepared {
    pub fn prompt(&self) -> &Prompt {
        &self.prompt
    }
    pub fn pending_state(&self) -> &Account {
        &self.after
    }
    pub fn private_account(&self) -> AccountId {
        self.private_account
    }
    pub(crate) fn operation(&self) -> NativeOperation {
        self.operation
    }
    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }
    pub(crate) fn check_public(&self, node: &impl ShieldedReader) -> Result<()> {
        if node.endpoint() != self.endpoint {
            return Err(Error::Invalid("private endpoint differs from approval"));
        }
        let state = node.native_view(self.operation.public_account)?;
        if state.nonce != self.public_nonce || state.native_balance()? != self.public_balance {
            return Err(Error::Invalid(
                "public state changed during private proving",
            ));
        }
        Ok(())
    }
}
pub struct Proven {
    transaction: PrivacyPreservingTransaction,
    pending: Account,
    private_account: AccountId,
    endpoint: String,
}
impl Proven {
    pub fn transaction(&self) -> &PrivacyPreservingTransaction {
        &self.transaction
    }
    pub fn pending_state(&self) -> &Account {
        &self.pending
    }
    pub fn private_account(&self) -> AccountId {
        self.private_account
    }
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}
fn up(id: AccountId) -> lee_v03::AccountId {
    lee_v03::AccountId::new(id.bytes())
}
fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| Error::Invalid("OS randomness unavailable"))?;
    Ok(bytes)
}

/// Caller supplies an opening only from its trusted encrypted wallet state.
/// Depositing into an absent opening creates the private account in the same proof.
pub fn prepare_native(
    policy: &mut Policy,
    app: &AppId,
    node: &impl ShieldedReader,
    identity: &PrivateIdentity,
    before: Option<&Account>,
    operation: NativeOperation,
    now: u64,
) -> Result<Prepared> {
    let private_account = identity.account();
    if !policy.permitted(app, Scope::Transactions, Some(private_account.bytes()))
        || (operation.direction == Direction::Deposit
            && !policy.permitted(
                app,
                Scope::Transactions,
                Some(operation.public_account.bytes()),
            ))
    {
        return Err(Error::Invalid("private transfer permission denied"));
    }
    if operation.amount == 0
        || operation.public_account == private_account
        || (before.is_none() && operation.direction == Direction::Withdrawal)
    {
        return Err(Error::Invalid("invalid private native operation"));
    }
    node.verify_privacy_circuit()?;
    let public = node.native_view(operation.public_account)?;
    let public_balance = public.native_balance()?;
    if operation.direction == Direction::Deposit
        && (public_balance < operation.amount || public.nonce == u128::MAX)
    {
        return Err(Error::Invalid(
            "insufficient public balance or exhausted nonce",
        ));
    }
    if operation.direction == Direction::Withdrawal
        && public_balance.checked_add(operation.amount).is_none()
    {
        return Err(Error::Invalid("public recipient balance overflow"));
    }
    let commitment = before.map(|state| Commitment::new(&up(private_account), state));
    let commitments: Vec<_> = commitment.into_iter().collect();
    let (proofs, root) = node.proofs_and_root(&commitments)?;
    validate_memberships(&commitments, &proofs, root)?;
    let membership = if before.is_some() {
        Some(proofs[0].clone().ok_or(Error::Invalid(
            "private opening is absent from commitment set",
        ))?)
    } else {
        None
    };
    let (after, nullifier) = identity.with_keys(|keys| -> Result<_> {
        let mut state = before.cloned().unwrap_or_default();
        let balance = state
            .data
            .native_balance()
            .map_err(|_| Error::Invalid("invalid private native balance"))?;
        let balance = match operation.direction {
            Direction::Deposit => balance.checked_add(operation.amount),
            Direction::Withdrawal => balance.checked_sub(operation.amount),
        }
        .ok_or(Error::Invalid(
            "private native balance overflow or insufficient funds",
        ))?;
        state.data.set_shard(
            native_token::NATIVE_TOKEN_PROGRAM_ID,
            native_token::encode_balance(balance),
        );
        let nsk = keys.nullifier_secret_key();
        state.nonce = before.map_or_else(
            || Nonce::private_account_nonce_init(&up(private_account)),
            |state| state.nonce.private_account_nonce_increment(&nsk),
        );
        let nullifier = commitment.map_or_else(
            || Nullifier::for_account_initialization(&up(private_account)),
            |c| Nullifier::for_account_update(&c, &nsk),
        );
        Ok((state, nullifier))
    })?;
    let mut digest = Sha256::new();
    digest.update(b"logos.wallet.v03.private.native.v1\0");
    digest.update((node.endpoint().len() as u64).to_le_bytes());
    digest.update(node.endpoint().as_bytes());
    digest.update(private_account.bytes());
    digest.update(operation.public_account.bytes());
    digest.update([if operation.direction == Direction::Deposit {
        0
    } else {
        1
    }]);
    digest.update(operation.amount.to_le_bytes());
    digest.update(public.nonce.to_le_bytes());
    digest.update(public_balance.to_le_bytes());
    digest.update(root);
    digest.update(Commitment::new(&up(private_account), &after).to_byte_array());
    digest.update(nullifier.to_byte_array());
    let source = if operation.direction == Direction::Deposit {
        operation.public_account
    } else {
        private_account
    };
    let destination = if operation.direction == Direction::Deposit {
        private_account
    } else {
        operation.public_account
    };
    let prompt=policy.request(app,Request::Transaction(Transaction{account:source.bytes(),message_hash:digest.finalize().into(),network:node.endpoint().into(),effects:vec![Effect::NativeTransfer{amount:operation.amount.to_string(),destination:destination.bytes()},Effect::ContractCall{program:[0;32],instruction:if operation.direction==Direction::Deposit{"Shield native currency".into()}else{"Unshield native currency".into()},explanation:"The public account and amount are visible. A local v0.3 proof publishes seven nullifiers, commitments and padded encrypted notes. The pinned protocol exempts private transactions from fees; this does not promise network anonymity or hide the public transfer.".into()}]}),now)?;
    Ok(Prepared {
        prompt,
        endpoint: node.endpoint().into(),
        operation,
        private_account,
        before: before.cloned(),
        after,
        public_nonce: public.nonce,
        public_balance,
        membership,
        root,
        nullifier,
    })
}
fn check_local_configuration(
    prover: Option<&str>,
    executor: Option<&str>,
    development: Option<&str>,
) -> Result<()> {
    if prover != Some("ipc") || executor != Some("ipc") || development != Some("0") {
        return Err(Error::Invalid(
            "private proving requires local IPC executor/prover and RISC0_DEV_MODE=0",
        ));
    }
    Ok(())
}
fn require_local_prover() -> Result<()> {
    check_local_configuration(
        std::env::var("RISC0_PROVER").ok().as_deref(),
        std::env::var("RISC0_EXECUTOR").ok().as_deref(),
        std::env::var("RISC0_DEV_MODE").ok().as_deref(),
    )?;
    let path =
        std::env::var_os("RISC0_SERVER_PATH").ok_or(Error::Invalid("local prover path missing"))?;
    let path = std::path::Path::new(&path);
    if !path.is_absolute() || !path.is_file() {
        return Err(Error::Invalid("local prover executable missing"));
    }
    Ok(())
}
fn verify_receipt(output: &PrivacyPreservingCircuitOutput, proof: &circuit::Proof) -> Result<()> {
    let inner: risc0_zkvm::InnerReceipt = borsh::from_slice(&proof.clone().into_inner())
        .map_err(|_| Error::Invalid("invalid private receipt encoding"))?;
    if matches!(inner, risc0_zkvm::InnerReceipt::Fake(_)) {
        return Err(Error::Invalid("development receipts are forbidden"));
    }
    risc0_zkvm::Receipt::new(inner, output.to_bytes())
        .verify(lee_v03::PRIVACY_PRESERVING_CIRCUIT_ID)
        .map_err(|_| Error::Invalid("private receipt verification failed"))
}
#[derive(Clone)]
struct ExpectedDummy {
    nullifier: Nullifier,
    commitment: Commitment,
    note: EncryptedAccountData,
}
fn dummy(root: [u8; 32]) -> Result<(DummyInput, ExpectedDummy)> {
    let nullifier_seed = random()?;
    let commitment_seed = random()?;
    let ek = lee_core_v03::encryption::shared_key_derivation::MlKem768EncapsulationKey::from_seed(
        &random()?,
        &random()?,
    );
    let (mut secret, epk) = SharedSecretKey::encapsulate(&ek);
    secret.0.zeroize();
    let note = EncryptedAccountData {
        ciphertext: Ciphertext::from_inner(random::<512>()?.to_vec()),
        epk,
        view_tag: random::<1>()?[0],
    };
    let nullifier = Nullifier::for_dummy(&nullifier_seed);
    let commitment = Commitment::for_dummy(&nullifier, &commitment_seed);
    Ok((
        DummyInput {
            nullifier_seed,
            commitment_seed,
            note: note.clone(),
            commitment_root: root,
        },
        ExpectedDummy {
            nullifier,
            commitment,
            note,
        },
    ))
}
fn validate_output(
    output: &PrivacyPreservingCircuitOutput,
    prepared: &Prepared,
    identity: &PrivateIdentity,
    dummies: &[ExpectedDummy],
    view_tag: u8,
) -> Result<()> {
    let deposit = prepared.operation.direction == Direction::Deposit;
    if !output.program_image_claims.is_empty()
        || output.block_validity_window != Default::default()
        || output.timestamp_validity_window != Default::default()
        || output.public_actions.len() != 1
        || output.private_actions.len() != dummies.len() + 1
    {
        return Err(Error::Invalid("unexpected private circuit effects"));
    }
    let public = &output.public_actions[0];
    let effect = if deposit {
        native_token::Effect::Debit(prepared.operation.amount)
    } else {
        native_token::Effect::Credit(prepared.operation.amount)
    };
    if public.account_id != up(prepared.operation.public_account)
        || public.is_authorized != deposit
        || public.effects
            != [lee_core_v03::execution_state::DeferredPublicEffect {
                program_account_id: native_token::NATIVE_TOKEN_PROGRAM_ID,
                shard_program_account_id: native_token::NATIVE_TOKEN_PROGRAM_ID,
                data: borsh::to_vec(&effect)
                    .map_err(|_| Error::Invalid("cannot encode private native effect"))?,
            }]
    {
        return Err(Error::Invalid(
            "private proof public effects differ from approval",
        ));
    }
    let mut commitments =
        BTreeSet::from([
            Commitment::new(&up(prepared.private_account), &prepared.after).to_byte_array(),
        ]);
    let mut nullifiers = BTreeSet::from([prepared.nullifier.to_byte_array()]);
    for dummy in dummies {
        if !commitments.insert(dummy.commitment.to_byte_array())
            || !nullifiers.insert(dummy.nullifier.to_byte_array())
        {
            return Err(Error::Invalid("duplicate private output"));
        }
    }
    for action in &output.private_actions {
        if action.root != prepared.root
            || !commitments.remove(&action.commitment.to_byte_array())
            || !nullifiers.remove(&action.nullifier.to_byte_array())
        {
            return Err(Error::Invalid(
                "unexpected private commitments or nullifiers",
            ));
        }
        if action.nullifier == prepared.nullifier {
            if action.encrypted_post_state.view_tag != view_tag {
                return Err(Error::Invalid("private view tag mismatch"));
            }
            identity.with_keys(|keys| -> Result<()> {
                let mut shared = SharedSecretKey::decapsulate(
                    &action.encrypted_post_state.epk,
                    &keys.d,
                    &keys.z,
                )
                .ok_or(Error::Invalid("invalid private note encapsulation"))?;
                let decoded = decrypt_quiet(
                    &action.encrypted_post_state.ciphertext,
                    &shared,
                    &action.nullifier,
                );
                shared.0.zeroize();
                let (kind, state) = decoded?;
                if kind != PrivateAccountKind::Regular(identity.identifier())
                    || state != prepared.after
                {
                    return Err(Error::Invalid("private output differs from approved state"));
                }
                Ok(())
            })?;
        } else if !dummies
            .iter()
            .any(|d| d.nullifier == action.nullifier && d.note == action.encrypted_post_state)
        {
            return Err(Error::Invalid("dummy note differs from supplied input"));
        }
    }
    Ok(())
}
/// Consumes one-use approval before local proving. This function never submits;
/// the wallet must durably save its result before attempting any broadcast.
pub fn prove_native(
    policy: &mut Policy,
    app: &AppId,
    node: &impl ShieldedReader,
    identity: &PrivateIdentity,
    public_key: Option<&PrivateKey>,
    prepared: &Prepared,
    now: u64,
) -> Result<Proven> {
    require_local_prover()?;
    let deposit = prepared.operation.direction == Direction::Deposit;
    if identity.account() != prepared.private_account
        || node.endpoint() != prepared.endpoint
        || public_key.map(|k| {
            AccountId::from_bytes(
                *lee_v03::AccountId::from(&PublicKey::new_from_private_key(k)).value(),
            )
        }) != deposit.then_some(prepared.operation.public_account)
    {
        return Err(Error::Invalid(
            "private identity, public signer or endpoint differs from approval",
        ));
    }
    if !policy.permitted(
        app,
        Scope::Transactions,
        Some(prepared.private_account.bytes()),
    ) {
        return Err(Error::Invalid("private transfer permission revoked"));
    }
    node.verify_privacy_circuit()?;
    let public = node.native_view(prepared.operation.public_account)?;
    if public.nonce != prepared.public_nonce || public.native_balance()? != prepared.public_balance
    {
        return Err(Error::Invalid(
            "public state changed; prepare a new private review",
        ));
    }
    let requested: Vec<_> = prepared
        .before
        .as_ref()
        .map(|state| Commitment::new(&up(prepared.private_account), state))
        .into_iter()
        .collect();
    let (proofs, root) = node.proofs_and_root(&requested)?;
    validate_memberships(&requested, &proofs, root)?;
    if root != prepared.root || prepared.before.is_some() && proofs[0].is_none() {
        return Err(Error::Invalid(
            "commitment state changed; prepare a new private review",
        ));
    }
    policy.consume(app, prepared.prompt.id, &prepared.prompt.request, now)?;
    let (witness, view_tag) = identity.with_keys(|keys| -> Result<_> {
        let view_tag = if prepared.before.is_none() {
            EncryptedAccountData::compute_view_tag(
                &keys.generate_nullifier_public_key(),
                &keys.generate_viewing_public_key(),
            )
        } else {
            random::<1>()?[0]
        };
        let nullifier = match &prepared.before {
            Some(account) => NullifierWitness::Update {
                account: account.clone(),
                view_tag,
                nsk: keys.nullifier_secret_key(),
                membership_proof: prepared
                    .membership
                    .clone()
                    .ok_or(Error::Invalid("private membership missing"))?,
            },
            None => NullifierWitness::Init {
                npk: keys.generate_nullifier_public_key(),
                commitment_root: prepared.root,
            },
        };
        Ok((
            PrivateWitness {
                vpk: keys.generate_viewing_public_key(),
                random_seed: random()?,
                identifier: identity.identifier(),
                kind: WitnessKind::Regular {
                    ask: Some(keys.authorization_secret_key),
                },
                nullifier,
            },
            view_tag,
        ))
    })?;
    let mut inputs = Vec::new();
    let mut expected = Vec::new();
    for _ in 0..6 {
        let (input, note) = dummy(prepared.root)?;
        inputs.push(input);
        expected.push(note);
    }
    let private = up(prepared.private_account);
    let public = up(prepared.operation.public_account);
    let (from, to) = if deposit {
        (public, private)
    } else {
        (private, public)
    };
    let (output, proof) = circuit::execute_and_prove(
        circuit::ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::native_balance(from),
                ProgramShardSelector::native_balance(to),
            ],
            signers: [from].into(),
            private_witnesses: vec![witness],
            instruction_data: borsh::to_vec(&native_token::Instruction::Transfer {
                amount: prepared.operation.amount,
            })
            .map_err(|_| Error::Invalid("cannot encode native instruction"))?,
            dummy_inputs: inputs,
            ciphertext_padding: Some(512),
        },
        &ProgramWithDependencies::native(),
    )
    .map_err(|error| {
        Error::Transport(match error {
            lee_v03::error::LeeError::CircuitProvingError(reason) => {
                format!("local private prover: {reason}")
            }
            other => format!("local private prover: {other}"),
        })
    })?;
    verify_receipt(&output, &proof)?;
    validate_output(&output, prepared, identity, &expected, view_tag)?;
    let message = Message::from_circuit_output(
        if deposit {
            vec![prepared.public_nonce.into()]
        } else {
            vec![]
        },
        output,
    );
    let keys: Vec<_> = public_key.into_iter().collect();
    let witness = WitnessSet::for_message(&message, proof, &keys);
    Ok(Proven {
        transaction: PrivacyPreservingTransaction::new(message, witness),
        pending: prepared.after.clone(),
        private_account: prepared.private_account,
        endpoint: prepared.endpoint.clone(),
    })
}

#[cfg(test)]
#[path = "shielded_tests.rs"]
mod tests;

pub const MAX_PRIVATE_WIRE: usize = 512 * 1024;
/// Rebuild the receipt journal from the saved signed message, including the
/// public authorization bits the sequencer derives from verified signatures.
pub(crate) fn verify_signed(transaction: &PrivacyPreservingTransaction) -> Result<()> {
    if !transaction
        .witness_set
        .signatures_are_valid_for(&transaction.message)
    {
        return Err(Error::Invalid("invalid private transaction signature"));
    }
    let signers: BTreeSet<_> = transaction
        .witness_set
        .signatures_and_public_keys()
        .iter()
        .map(|(_, key)| lee_v03::AccountId::from(key))
        .collect();
    if signers.len() != transaction.witness_set.signatures_and_public_keys().len()
        || signers.len() != transaction.message.nonces.len()
    {
        return Err(Error::Invalid("invalid private signer/nonces"));
    }
    let message = &transaction.message;
    let output = PrivacyPreservingCircuitOutput {
        public_actions: message
            .public_actions
            .iter()
            .map(|a| lee_core_v03::PublicAction {
                account_id: a.account_id,
                is_authorized: signers.contains(&a.account_id),
                effects: a.effects.clone(),
            })
            .collect(),
        private_actions: message.private_actions.clone(),
        block_validity_window: message.block_validity_window,
        timestamp_validity_window: message.timestamp_validity_window,
        program_image_claims: message.program_image_claims.clone(),
    };
    verify_receipt(&output, transaction.witness_set.proof())
}
pub trait PrivateSubmissionNode: ShieldedReader {
    fn broadcast_private(&self, transaction: &PrivacyPreservingTransaction) -> Result<[u8; 32]>;
    fn observed_private(&self, transaction: &PrivacyPreservingTransaction) -> Result<bool>;
}
impl PrivateSubmissionNode for Node {
    fn broadcast_private(&self, transaction: &PrivacyPreservingTransaction) -> Result<[u8; 32]> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let bytes = borsh::to_vec(transaction)
            .map_err(|_| Error::Invalid("cannot encode private transaction"))?;
        if bytes.len() > MAX_PRIVATE_WIRE {
            return Err(Error::Invalid(
                "private transaction exceeds wallet wire limit",
            ));
        }
        verify_signed(transaction)?;
        let mut wire = vec![1];
        wire.extend(bytes);
        let response: String = self.read("sendTransaction", json!([STANDARD.encode(wire)]))?;
        let hash: [u8; 32] = hex::decode(response)
            .map_err(|_| Error::Invalid("invalid private submission hash"))?
            .try_into()
            .map_err(|_| Error::Invalid("invalid private submission hash length"))?;
        if hash != transaction.hash() {
            return Err(Error::Invalid("private submission hash mismatch"));
        }
        Ok(hash)
    }
    fn observed_private(&self, transaction: &PrivacyPreservingTransaction) -> Result<bool> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let response: Option<(String, u64)> =
            self.read("getTransaction", json!([hex::encode(transaction.hash())]))?;
        let Some((encoded, _)) = response else {
            return Ok(false);
        };
        if encoded.len() > (MAX_PRIVATE_WIRE + 1) * 4 / 3 + 4 {
            return Err(Error::Invalid("oversized private confirmation"));
        }
        let received = STANDARD
            .decode(encoded)
            .map_err(|_| Error::Invalid("invalid private confirmation encoding"))?;
        let mut expected = vec![1];
        expected.extend(
            borsh::to_vec(transaction)
                .map_err(|_| Error::Invalid("cannot encode saved private transaction"))?,
        );
        if received != expected {
            return Err(Error::Invalid(
                "private confirmation differs from saved transaction",
            ));
        }
        Ok(true)
    }
}
