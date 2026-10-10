// SPDX-License-Identifier: MIT OR Apache-2.0
//! Encrypted multi-account lifecycle. Only the trusted wallet process opens this store.
pub mod public_outbox;
pub mod sync;
use key_protocol::key_management::{
    KeyChain,
    secret_holders::{PrivateKeyHolder, SecretSpendingKey},
};
use lee::{AccountId, PrivateKey, PublicKey};
use lee_core::PrivateAccountKind;
use logos_wallet_policy::{Grant, Policy, principal::Principal};
use logos_wallet_store::Store;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Node(#[from] logos_registry_sdk::Error),
    #[error(transparent)]
    Store(#[from] logos_wallet_store::Error),
    #[error("Invalid wallet account data")]
    Invalid,
    #[error("Select the transaction's original sequencer before checking its status")]
    SubmissionNetwork,
    #[error("Account is already imported")]
    Duplicate,
    #[error("Account not found")]
    NotFound,
    #[error("This is a private account; use the shielded transaction executor")]
    PrivateAccount,
    #[error("Private operation is pending; confirm or synchronize it before another transfer")]
    PrivatePending,
    #[error("Private pre-state differs from the last included wallet state")]
    PrivateStateChanged,
    #[error(
        "Transaction does not advance this account from its recorded state; recover intermediate transactions first"
    )]
    RecoveryMismatch,
    #[error(
        "Node history differs from the wallet checkpoint; refusing to label cached state current"
    )]
    HistoryChanged,
}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountSecret {
    label: String,
    key: [u8; 32],
    #[serde(default)]
    privacy: Privacy,
}
#[derive(Clone, Default, Serialize, Deserialize)]
enum Privacy {
    #[default]
    Public,
    Private {
        identifier: u128,
    },
}
impl Drop for AccountSecret {
    fn drop(&mut self) {
        self.key.zeroize();
        self.label.zeroize();
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Book {
    schema: u16,
    selected: Option<[u8; 32]>,
    accounts: Vec<AccountSecret>,
    #[serde(default)]
    private_initializations: Vec<PrivateInitialization>,
    #[serde(default)]
    private_scans: Vec<sync::Cursor>,
    #[serde(default)]
    provider_grants: Vec<ProviderGrant>,
    #[serde(default)]
    public_submissions: Vec<public_outbox::Submission>,
}
/// Trusted wallet settings only. Not a provider response: it contains other
/// applications' permissions and selected account identities.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderGrant {
    pub principal: Principal,
    pub grant: Grant,
}
/// Encrypted recovery record. Inclusion is a node claim, never consensus finality.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateInitialization {
    endpoint: String,
    account: AccountId,
    transaction: common::transaction::LeeTransaction,
    state: lee::Account,
    included: bool,
    #[serde(default)]
    previous: Option<PreviousPrivateState>,
    #[serde(default)]
    replaced_pending: Option<common::HashType>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviousPrivateState {
    transaction_hash: common::HashType,
    state: lee::Account,
}
#[derive(Serialize)]
pub struct PrivateRecovery {
    pub account: AccountId,
    pub transaction: common::HashType,
    pub replaced_pending: Option<common::HashType>,
}
#[derive(Debug, Serialize)]
pub struct AccountInfo {
    pub account: AccountId,
    pub label: String,
    pub selected: bool,
    pub privacy: &'static str,
}
pub struct Keyring {
    store: Store,
    revision: u64,
    password: Zeroizing<Vec<u8>>,
    book: Book,
}
fn identity(secret: &AccountSecret) -> Result<AccountId> {
    if let Privacy::Private { identifier } = secret.privacy {
        let holder = SecretSpendingKey(secret.key).produce_private_key_holder(None);
        return Ok(AccountId::for_private_account(
            &holder.generate_nullifier_public_key(),
            &holder.generate_viewing_public_key(),
            &PrivateAccountKind::Regular(identifier),
        ));
    }
    let key = PrivateKey::try_new(secret.key).map_err(|_| Error::Invalid)?;
    Ok(AccountId::from(&PublicKey::new_from_private_key(&key)))
}
fn validate(book: &Book) -> Result<()> {
    if book.schema != 1
        || book.accounts.len() > 256
        || book.private_initializations.len() > 256
        || book.private_scans.len() > 256
        || book.provider_grants.len() > 256
        || book.public_submissions.len() > 256
    {
        return Err(Error::Invalid);
    }
    let mut accounts = BTreeSet::new();
    let mut private_accounts = BTreeSet::new();
    for secret in &book.accounts {
        if secret.label.trim().is_empty()
            || secret.label.len() > 100
            || secret.label.chars().any(char::is_control)
        {
            return Err(Error::Invalid);
        }
        let account = *identity(secret)?.value();
        if !accounts.insert(account) {
            return Err(Error::Invalid);
        }
        if matches!(secret.privacy, Privacy::Private { .. }) {
            private_accounts.insert(account);
        }
    }
    if book.selected.is_some_and(|id| !accounts.contains(&id))
        || (!accounts.is_empty() && book.selected.is_none())
    {
        return Err(Error::Invalid);
    }
    let mut principals = BTreeSet::new();
    let mut policy = Policy::default();
    for record in &book.provider_grants {
        let app = record.principal.policy_id().map_err(|_| Error::Invalid)?;
        if !principals.insert(app.clone()) || !record.grant.accounts.is_subset(&accounts) {
            return Err(Error::Invalid);
        }
        policy
            .set_grant(app, record.grant.clone())
            .map_err(|_| Error::Invalid)?;
    }
    public_outbox::validate(&book.public_submissions, &accounts, &private_accounts)?;
    let mut records = BTreeSet::new();
    for record in &book.private_initializations {
        if !private_accounts.contains(record.account.value())
            || (record.included && record.previous.is_some())
            || record.endpoint.is_empty()
            || record.endpoint.len() > 2048
            || !records.insert((record.endpoint.clone(), *record.account.value()))
        {
            return Err(Error::Invalid);
        }
    }
    let mut scans = BTreeSet::new();
    for cursor in &book.private_scans {
        if !private_accounts.contains(cursor.account.value())
            || cursor.endpoint.is_empty()
            || cursor.endpoint.len() > 2048
            || !scans.insert((cursor.endpoint.clone(), cursor.account))
        {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}
fn encode(book: &Book) -> Result<Zeroizing<Vec<u8>>> {
    validate(book)?;
    Ok(Zeroizing::new(
        serde_json::to_vec(book).map_err(|_| Error::Invalid)?,
    ))
}
impl Keyring {
    pub fn create(path: &Path, password: &[u8]) -> Result<Self> {
        let book = Book {
            schema: 1,
            selected: None,
            accounts: vec![],
            private_initializations: vec![],
            private_scans: vec![],
            provider_grants: vec![],
            public_submissions: vec![],
        };
        let store = Store::create(path, password, &encode(&book)?)?;
        Ok(Self {
            store,
            revision: 0,
            password: Zeroizing::new(password.to_vec()),
            book,
        })
    }
    pub fn open(path: &Path, password: &[u8]) -> Result<Self> {
        let store = Store::open(path)?;
        let snapshot = store.load(password)?;
        let book: Book = serde_json::from_slice(&snapshot.payload).map_err(|_| Error::Invalid)?;
        validate(&book)?;
        Ok(Self {
            store,
            revision: snapshot.revision,
            password: Zeroizing::new(password.to_vec()),
            book,
        })
    }
    /// Write a fresh encrypted SQLite snapshot, never overwriting a destination.
    /// Includes keys, grants, scan checkpoints and pending submission recovery.
    pub fn backup(&self, destination: &Path, password: &[u8]) -> Result<()> {
        self.ensure_current()?;
        if password.is_empty() || password.len() > 4096 || !destination.is_absolute() {
            return Err(Error::Invalid);
        }
        drop(Store::create(destination, password, &encode(&self.book)?)?);
        Ok(())
    }
    /// Restore into a new database only. The source backup is retained.
    /// Cached chain state must still be reconciled against its original endpoint.
    pub fn restore(source: &Path, destination: &Path, password: &[u8]) -> Result<Self> {
        if source == destination || !source.is_absolute() || !destination.is_absolute() {
            return Err(Error::Invalid);
        }
        let backup = Self::open(source, password)?;
        backup.backup(destination, password)?;
        Self::open(destination, password)
    }
    fn commit(&mut self, book: Book) -> Result<()> {
        let revision = self
            .store
            .save(&self.password, self.revision, &encode(&book)?)?;
        self.book = book;
        self.revision = revision;
        Ok(())
    }
    /// Reject stale unlocked sessions before disclosing permission-gated data.
    /// This authenticates the saved snapshot; it is not whole-file rollback protection.
    pub fn ensure_current(&self) -> Result<()> {
        let snapshot = self.store.load(&self.password)?;
        if snapshot.revision != self.revision {
            return Err(Error::Store(logos_wallet_store::Error::Conflict));
        }
        Ok(())
    }
    /// Rebuild permissions after unlock. Pending approvals are intentionally
    /// absent: a restart never restores signing/proof authorization.
    pub fn provider_policy(&self) -> Result<Policy> {
        let mut policy = Policy::default();
        for record in &self.book.provider_grants {
            let app = record.principal.policy_id().map_err(|_| Error::Invalid)?;
            policy
                .set_grant(app, record.grant.clone())
                .map_err(|_| Error::Invalid)?;
        }
        Ok(policy)
    }
    pub fn provider_grants(&self) -> &[ProviderGrant] {
        &self.book.provider_grants
    }
    /// Trusted wallet UI only, after explicit scope/account selection. The
    /// encrypted CAS commit happens before any caller receives permission.
    pub fn set_provider_grant(&mut self, principal: Principal, grant: Grant) -> Result<()> {
        principal.validate().map_err(|_| Error::Invalid)?;
        let mut book = self.book.clone();
        book.provider_grants
            .retain(|record| record.principal != principal);
        book.provider_grants
            .push(ProviderGrant { principal, grant });
        self.commit(book)
    }
    pub fn revoke_provider_grant(&mut self, principal: &Principal) -> Result<()> {
        let mut book = self.book.clone();
        book.provider_grants
            .retain(|record| &record.principal != principal);
        self.commit(book)
    }
    pub fn accounts(&self) -> Result<Vec<AccountInfo>> {
        self.book
            .accounts
            .iter()
            .map(|secret| {
                let account = identity(secret)?;
                Ok(AccountInfo {
                    selected: self.book.selected == Some(*account.value()),
                    account,
                    label: secret.label.clone(),
                    privacy: match secret.privacy {
                        Privacy::Public => "public",
                        Privacy::Private { .. } => "private",
                    },
                })
            })
            .collect()
    }
    /// Produces a local key; initialization/funding is a separate approved chain action.
    pub fn generate_public(&mut self, label: &str) -> Result<AccountId> {
        let key = PrivateKey::new_os_random();
        self.import_public(label, key.value())
    }
    pub fn import_public(&mut self, label: &str, key: &[u8; 32]) -> Result<AccountId> {
        let secret = AccountSecret {
            label: label.into(),
            key: *key,
            privacy: Privacy::Public,
        };
        let account = identity(&secret)?;
        if self
            .book
            .accounts
            .iter()
            .any(|a| identity(a).ok() == Some(account))
        {
            return Err(Error::Duplicate);
        }
        let mut book = self.book.clone();
        book.accounts.push(secret);
        if book.selected.is_none() {
            book.selected = Some(*account.value());
        }
        self.commit(book)?;
        Ok(account)
    }
    pub fn select(&mut self, account: AccountId) -> Result<()> {
        if !self
            .book
            .accounts
            .iter()
            .any(|a| identity(a).ok() == Some(account))
        {
            return Err(Error::NotFound);
        }
        let mut book = self.book.clone();
        book.selected = Some(*account.value());
        self.commit(book)
    }
    pub fn rename(&mut self, account: AccountId, label: &str) -> Result<()> {
        let mut book = self.book.clone();
        let secret = book
            .accounts
            .iter_mut()
            .find(|a| identity(a).ok() == Some(account))
            .ok_or(Error::NotFound)?;
        secret.label.zeroize();
        secret.label = label.into();
        self.commit(book)
    }
    /// Trusted signing path only. No provider-facing key export or account deletion API.
    pub fn signing_key(&self, account: AccountId) -> Result<PrivateKey> {
        let secret = self
            .book
            .accounts
            .iter()
            .find(|a| identity(a).ok() == Some(account))
            .ok_or(Error::NotFound)?;
        if matches!(secret.privacy, Privacy::Private { .. }) {
            return Err(Error::PrivateAccount);
        }
        PrivateKey::try_new(secret.key).map_err(|_| Error::Invalid)
    }
    pub fn selected_signing_key(&self) -> Result<PrivateKey> {
        self.signing_key(AccountId::new(self.book.selected.ok_or(Error::NotFound)?))
    }
    pub fn selected_account(&self) -> Result<AccountId> {
        Ok(AccountId::new(self.book.selected.ok_or(Error::NotFound)?))
    }
    /// Uses the pinned LEZ key protocol, never a public signing key disguised as private.
    pub fn generate_private(&mut self, label: &str) -> Result<AccountId> {
        let keys = KeyChain::new_os_random();
        let secret = AccountSecret {
            label: label.into(),
            key: keys.secret_spending_key.0,
            privacy: Privacy::Private { identifier: 0 },
        };
        let account = identity(&secret)?;
        let mut book = self.book.clone();
        book.accounts.push(secret);
        if book.selected.is_none() {
            book.selected = Some(*account.value());
        }
        self.commit(book)?;
        Ok(account)
    }
    /// Trusted shielded executor only; never expose secret holders over provider IPC.
    pub fn private_keys(
        &self,
        account: AccountId,
    ) -> Result<(PrivateKeyHolder, PrivateAccountKind)> {
        let secret = self
            .book
            .accounts
            .iter()
            .find(|a| identity(a).ok() == Some(account))
            .ok_or(Error::NotFound)?;
        let Privacy::Private { identifier } = secret.privacy else {
            return Err(Error::Invalid);
        };
        Ok((
            SecretSpendingKey(secret.key).produce_private_key_holder(None),
            PrivateAccountKind::Regular(identifier),
        ))
    }
    pub fn rotate_password(&mut self, new: &[u8]) -> Result<()> {
        let revision = self
            .store
            .rotate_password(&self.password, new, self.revision)?;
        self.password = Zeroizing::new(new.to_vec());
        self.revision = revision;
        Ok(())
    }
    /// Trusted executor only. Save before submission so an uncertain response or
    /// process crash can be recovered using the exact proven transaction hash.
    pub fn retain_private_initialization(
        &mut self,
        proven: &crate::shielded::ProvenInitialization,
    ) -> Result<()> {
        self.private_keys(proven.account)?;
        if self
            .book
            .private_initializations
            .iter()
            .any(|r| r.endpoint == proven.endpoint && r.account == proven.account)
        {
            return Err(Error::Duplicate);
        }
        let mut book = self.book.clone();
        book.private_initializations.push(PrivateInitialization {
            endpoint: proven.endpoint.clone(),
            account: proven.account,
            transaction: proven.transaction.clone(),
            state: proven.pending_state.clone(),
            included: false,
            previous: None,
            replaced_pending: None,
        });
        self.commit(book)
    }
    /// Trusted local recovery only; never expose the complete wallet over provider IPC.
    pub fn pending_private_initialization(
        &self,
        endpoint: &str,
        account: AccountId,
    ) -> Result<(common::HashType, bool)> {
        self.pending_private_operation(endpoint, account)
    }
    pub fn pending_private_operation(
        &self,
        endpoint: &str,
        account: AccountId,
    ) -> Result<(common::HashType, bool)> {
        let record = self
            .book
            .private_initializations
            .iter()
            .find(|r| r.endpoint == endpoint && r.account == account)
            .ok_or(Error::NotFound)?;
        Ok((record.transaction.hash(), record.included))
    }
    /// Last included state only, not a claim that external activity has been synchronized.
    /// A pending update blocks use of this snapshot for a second outgoing operation.
    pub fn last_included_private_state(
        &self,
        endpoint: &str,
        account: AccountId,
    ) -> Result<lee::Account> {
        let record = self
            .book
            .private_initializations
            .iter()
            .find(|r| r.endpoint == endpoint && r.account == account)
            .ok_or(Error::NotFound)?;
        if !record.included {
            return Err(Error::PrivatePending);
        }
        Ok(record.state.clone())
    }
    /// Persists the exact proven update before submission. Keep the previous
    /// included opening while pending, so a failed submission cannot erase it.
    pub fn retain_private_transfer(
        &mut self,
        proven: &crate::shielded_transfer::Proven,
    ) -> Result<()> {
        self.retain_private_transfers(&[proven])
    }
    /// Atomically retain every owned private update from one proven transaction.
    /// Both sides of a private-to-private transfer must be durable before broadcast.
    /// `Proven` values are constructed only by the trusted proof adapter.
    pub fn retain_private_transfers(
        &mut self,
        updates: &[&crate::shielded_transfer::Proven],
    ) -> Result<()> {
        let Some(first) = updates.first() else {
            return Err(Error::Invalid);
        };
        if updates.len() > 2 {
            return Err(Error::Invalid);
        }
        let hash = first.transaction.hash();
        let mut accounts = BTreeSet::new();
        let mut book = self.book.clone();
        for proven in updates {
            if proven.endpoint != first.endpoint
                || proven.transaction.hash() != hash
                || !accounts.insert(proven.account)
            {
                return Err(Error::Invalid);
            }
            let record = book
                .private_initializations
                .iter_mut()
                .find(|r| r.endpoint == proven.endpoint && r.account == proven.account)
                .ok_or(Error::NotFound)?;
            if !record.included {
                return Err(Error::PrivatePending);
            }
            if lee_core::Commitment::new(&record.account, &record.state) != proven.pre_commitment {
                return Err(Error::PrivateStateChanged);
            }
            record.previous = Some(PreviousPrivateState {
                transaction_hash: record.transaction.hash(),
                state: record.state.clone(),
            });
            record.transaction = proven.transaction.clone();
            record.state = proven.pending_state.clone();
            record.included = false;
        }
        self.commit(book)
    }
    /// Queries the exact recorded transaction. A missing/error response leaves
    /// the pending record intact. This does not establish the latest balance.
    pub fn confirm_private_initialization(
        &mut self,
        endpoint: &str,
        account: AccountId,
    ) -> std::result::Result<bool, crate::Error> {
        self.confirm_private_operation(endpoint, account)
    }
    pub fn confirm_private_operation(
        &mut self,
        endpoint: &str,
        account: AccountId,
    ) -> std::result::Result<bool, crate::Error> {
        let (hash, _) = self
            .pending_private_operation(endpoint, account)
            .map_err(|_| crate::Error::Invalid("Private operation record missing"))?;
        let node = logos_registry_sdk::HttpNode::new(endpoint)?;
        if !node.confirmed(hash)? {
            return Ok(false);
        }
        let mut book = self.book.clone();
        let record = book
            .private_initializations
            .iter_mut()
            .find(|r| r.endpoint == endpoint && r.account == account)
            .ok_or(crate::Error::Invalid("Private operation record missing"))?;
        node.commitment_membership(lee_core::Commitment::new(&account, &record.state))?;
        record.included = true;
        record.previous = None;
        self.commit(book).map_err(|_| {
            crate::Error::Invalid("Could not save private inclusion; record remains pending")
        })?;
        Ok(true)
    }
    /// Recover only a cryptographically checked initialization or the immediate
    /// successor to the stored state. This is explicit hash recovery, not scanning
    /// for the latest state or an independent consensus/finality check.
    pub fn recover_private_transaction(
        &mut self,
        endpoint: &str,
        account: AccountId,
        hash: common::HashType,
    ) -> Result<Option<PrivateRecovery>> {
        use lee_core::{Commitment, Nullifier};
        let (keys, kind) = self.private_keys(account)?;
        let node = logos_registry_sdk::HttpNode::new(endpoint)?;
        let Some(transaction) = node.confirmed_transaction(hash)? else {
            return Ok(None);
        };
        let common::transaction::LeeTransaction::PrivacyPreserving(private) = &transaction else {
            return Err(Error::RecoveryMismatch);
        };
        let record = self
            .book
            .private_initializations
            .iter()
            .find(|r| r.endpoint == endpoint && r.account == account);
        let same = record.is_some_and(|r| r.transaction.hash() == hash);
        let before = record.and_then(|r| {
            if r.included {
                Some(&r.state)
            } else {
                r.previous.as_ref().map(|p| &p.state)
            }
        });
        // An already recorded transaction is checked against its exact output;
        // otherwise require the next nullifier, preventing a rollback/skip.
        let expected_nullifier = before.map_or_else(
            || Nullifier::for_account_initialization(&account),
            |state| {
                Nullifier::for_account_update(
                    &Commitment::new(&account, state),
                    &keys.nullifier_secret_key,
                )
            },
        );
        let expected_nonce = before.map_or_else(
            || lee_core::account::Nonce::private_account_nonce_init(&account),
            |state| {
                state
                    .nonce
                    .private_account_nonce_increment(&keys.nullifier_secret_key)
            },
        );
        let expectation = if same {
            crate::private_output::Expected::Recorded(&record.ok_or(Error::RecoveryMismatch)?.state)
        } else {
            crate::private_output::Expected::Successor {
                nullifier: expected_nullifier,
                nonce: expected_nonce,
            }
        };
        let state = crate::private_output::recover(
            &private.message.private_actions,
            &keys,
            &kind,
            account,
            expectation,
        )
        .ok_or(Error::RecoveryMismatch)?;
        node.commitment_membership(Commitment::new(&account, &state))?;
        let replaced_pending = record
            .filter(|r| !r.included && r.transaction.hash() != hash)
            .map(|r| r.transaction.hash());
        let updated = PrivateInitialization {
            endpoint: endpoint.into(),
            account,
            transaction,
            state,
            included: true,
            previous: None,
            replaced_pending,
        };
        let mut book = self.book.clone();
        if let Some(existing) = book
            .private_initializations
            .iter_mut()
            .find(|r| r.endpoint == endpoint && r.account == account)
        {
            *existing = updated;
        } else {
            book.private_initializations.push(updated);
        }
        self.commit(book)?;
        Ok(Some(PrivateRecovery {
            account,
            transaction: hash,
            replaced_pending,
        }))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_backup_restore_preserves_keys_and_refuses_overwrite_and_stale_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.sqlite");
        let backup = dir.path().join("backup.sqlite");
        let restored = dir.path().join("restored.sqlite");
        let mut ring = Keyring::create(&path, b"source password").unwrap();
        ring.generate_public("public backup fixture").unwrap();
        let private = ring.generate_private("private backup fixture").unwrap();
        ring.select(private).unwrap();
        let mut book = ring.book.clone();
        book.provider_grants.push(ProviderGrant {
            principal: Principal::Module {
                name: "backup_fixture".into(),
                instance: String::new(),
            },
            grant: Grant {
                accounts: [*private.value()].into_iter().collect(),
                scopes: [logos_wallet_policy::Scope::Accounts].into_iter().collect(),
            },
        });
        // Storage-only sentinel, not a valid private transaction/proof.
        book.private_initializations.push(PrivateInitialization {
            endpoint: "http://127.0.0.1:1".into(),
            account: private,
            transaction: common::transaction::LeeTransaction::ProgramDeployment(
                lee::ProgramDeploymentTransaction::new(
                    lee::program_deployment_transaction::Message::new(vec![1]),
                ),
            ),
            state: lee::Account::default(),
            included: false,
            previous: None,
            replaced_pending: None,
        });
        ring.commit(book).unwrap();
        let stale = Keyring::open(&path, b"source password").unwrap();
        ring.rename(private, "renamed private").unwrap();
        assert!(stale.backup(&backup, b"backup password").is_err());
        assert!(!backup.exists());
        ring.backup(&backup, b"backup password").unwrap();
        let bytes = std::fs::read(&backup).unwrap();
        assert!(
            !bytes
                .windows(b"renamed private".len())
                .any(|w| w == b"renamed private")
        );
        assert!(ring.backup(&backup, b"replacement password").is_err());
        assert_eq!(bytes, std::fs::read(&backup).unwrap());
        assert!(Keyring::restore(&backup, &restored, b"wrong password").is_err());
        assert!(!restored.exists());
        let recovered = Keyring::restore(&backup, &restored, b"backup password").unwrap();
        assert_eq!(recovered.selected_account().unwrap(), private);
        assert_eq!(
            *encode(&recovered.book).unwrap(),
            *encode(&ring.book).unwrap()
        );
        assert_eq!(
            serde_json::to_value(recovered.accounts().unwrap()).unwrap(),
            serde_json::to_value(ring.accounts().unwrap()).unwrap()
        );
        assert!(recovered.private_keys(private).unwrap() == ring.private_keys(private).unwrap());
        assert!(Keyring::restore(&backup, &restored, b"backup password").is_err());
        assert!(Keyring::open(&path, b"source password").is_ok());
    }

    #[test]
    fn private_pending_blocks_reuse_and_survives_stale_writers_and_restart() {
        // Storage-only fixture: this transaction is not a private proof. Genuine
        // receipt/decryption/inclusion checks are exercised by the prover harness.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pending.sqlite");
        let mut ring = Keyring::create(&path, b"local pending fixture").unwrap();
        let account = ring.generate_private("Storage fixture").unwrap();
        let endpoint = "http://127.0.0.1:1";
        let old = lee::Account {
            program_owner: programs::authenticated_transfer().id(),
            balance: 10,
            ..Default::default()
        };
        let transaction = common::transaction::LeeTransaction::ProgramDeployment(
            lee::ProgramDeploymentTransaction::new(
                lee::program_deployment_transaction::Message::new(vec![1]),
            ),
        );
        let mut book = ring.book.clone();
        book.private_initializations.push(PrivateInitialization {
            endpoint: endpoint.into(),
            account,
            transaction: transaction.clone(),
            state: old.clone(),
            included: true,
            previous: None,
            replaced_pending: None,
        });
        ring.commit(book).unwrap();
        let mut stale = Keyring::open(&path, b"local pending fixture").unwrap();
        let updated = lee::Account {
            balance: 11,
            ..old.clone()
        };
        let mut proven = crate::shielded_transfer::Proven {
            endpoint: endpoint.into(),
            account,
            pre_commitment: lee_core::Commitment::new(&account, &updated),
            transaction,
            pending_state: updated,
        };
        assert!(matches!(
            ring.retain_private_transfer(&proven),
            Err(Error::PrivateStateChanged)
        ));
        assert_eq!(
            ring.last_included_private_state(endpoint, account)
                .unwrap()
                .balance,
            10
        );
        proven.pre_commitment = lee_core::Commitment::new(&account, &old);
        ring.retain_private_transfer(&proven).unwrap();
        assert!(matches!(
            ring.last_included_private_state(endpoint, account),
            Err(Error::PrivatePending)
        ));
        assert!(matches!(
            ring.retain_private_transfer(&proven),
            Err(Error::PrivatePending)
        ));
        assert!(matches!(
            stale.retain_private_transfer(&proven),
            Err(Error::Store(_))
        ));
        drop(ring);
        let restored = Keyring::open(&path, b"local pending fixture").unwrap();
        assert_eq!(
            restored
                .pending_private_operation(endpoint, account)
                .unwrap(),
            (proven.transaction.hash(), false)
        );
        assert_eq!(
            restored.book.private_initializations[0]
                .previous
                .as_ref()
                .unwrap()
                .state
                .balance,
            10
        );
        assert!(matches!(
            restored.last_included_private_state(endpoint, account),
            Err(Error::PrivatePending)
        ));
    }
    #[test]
    fn private_pair_retention_is_atomic_and_survives_restart() {
        // Persistence fixture only: not a cryptographic proof or chain execution.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pair.sqlite");
        let password = b"private pair storage fixture";
        let mut ring = Keyring::create(&path, password).unwrap();
        let from = ring.generate_private("Sender").unwrap();
        let to = ring.generate_private("Recipient").unwrap();
        let endpoint = "http://127.0.0.1:1";
        let transaction = common::transaction::LeeTransaction::ProgramDeployment(
            lee::ProgramDeploymentTransaction::new(
                lee::program_deployment_transaction::Message::new(vec![2]),
            ),
        );
        let mut book = ring.book.clone();
        let mut updates = Vec::new();
        for (account, before, after) in [(from, 10, 6), (to, 2, 6)] {
            let state = lee::Account {
                balance: before,
                ..Default::default()
            };
            book.private_initializations.push(PrivateInitialization {
                endpoint: endpoint.into(),
                account,
                transaction: transaction.clone(),
                state: state.clone(),
                included: true,
                previous: None,
                replaced_pending: None,
            });
            updates.push(crate::shielded_transfer::Proven {
                endpoint: endpoint.into(),
                account,
                pre_commitment: lee_core::Commitment::new(&account, &state),
                transaction: transaction.clone(),
                pending_state: lee::Account {
                    balance: after,
                    ..state
                },
            });
        }
        ring.commit(book).unwrap();
        let mut stale = Keyring::open(&path, password).unwrap();
        let original_bytes = std::fs::read(&path).unwrap();
        assert!(matches!(
            ring.retain_private_transfers(&[]),
            Err(Error::Invalid)
        ));
        assert!(matches!(
            ring.retain_private_transfers(&[&updates[0], &updates[0]]),
            Err(Error::Invalid)
        ));
        let correct = updates[1].pre_commitment;
        updates[1].pre_commitment = updates[0].pre_commitment;
        assert!(matches!(
            ring.retain_private_transfers(&[&updates[0], &updates[1]]),
            Err(Error::PrivateStateChanged)
        ));
        updates[1].pre_commitment = correct;
        updates[1].endpoint = "http://127.0.0.1:2".into();
        assert!(matches!(
            ring.retain_private_transfers(&[&updates[0], &updates[1]]),
            Err(Error::Invalid)
        ));
        updates[1].endpoint = endpoint.into();
        updates[1].transaction = common::transaction::LeeTransaction::ProgramDeployment(
            lee::ProgramDeploymentTransaction::new(
                lee::program_deployment_transaction::Message::new(vec![3]),
            ),
        );
        assert!(matches!(
            ring.retain_private_transfers(&[&updates[0], &updates[1]]),
            Err(Error::Invalid)
        ));
        updates[1].transaction = transaction.clone();
        assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
        assert_eq!(
            ring.last_included_private_state(endpoint, from)
                .unwrap()
                .balance,
            10
        );
        assert_eq!(
            ring.last_included_private_state(endpoint, to)
                .unwrap()
                .balance,
            2
        );
        ring.retain_private_transfers(&[&updates[0], &updates[1]])
            .unwrap();
        assert!(matches!(
            stale.retain_private_transfers(&[&updates[0], &updates[1]]),
            Err(Error::Store(_))
        ));
        drop(ring);
        let restored = Keyring::open(&path, password).unwrap();
        for (account, before) in [(from, 10), (to, 2)] {
            assert_eq!(
                restored
                    .pending_private_operation(endpoint, account)
                    .unwrap(),
                (transaction.hash(), false)
            );
            assert!(matches!(
                restored.last_included_private_state(endpoint, account),
                Err(Error::PrivatePending)
            ));
            let record = restored
                .book
                .private_initializations
                .iter()
                .find(|r| r.account == account)
                .unwrap();
            assert_eq!(record.state.balance, 6);
            assert_eq!(record.previous.as_ref().unwrap().state.balance, before);
        }
    }
    #[test]
    fn private_key_protocol_roundtrip_never_uses_public_signer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private.sqlite");
        let mut ring = Keyring::create(&path, b"private fixture password").unwrap();
        let account = ring.generate_private("Private fixture").unwrap();
        let (keys, kind) = ring.private_keys(account).unwrap();
        assert_eq!(
            account,
            AccountId::for_private_account(
                &keys.generate_nullifier_public_key(),
                &keys.generate_viewing_public_key(),
                &kind
            )
        );
        assert!(matches!(
            ring.selected_signing_key(),
            Err(Error::PrivateAccount)
        ));
        drop(ring);
        let ring = Keyring::open(&path, b"private fixture password").unwrap();
        assert_eq!(ring.accounts().unwrap()[0].privacy, "private");
        let (restored, restored_kind) = ring.private_keys(account).unwrap();
        assert!(keys == restored);
        assert!(kind == restored_kind);
        assert!(matches!(
            ring.signing_key(account),
            Err(Error::PrivateAccount)
        ));
    }
    #[test]
    fn accounts_survive_restart_selection_and_failed_concurrent_update() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let mut first = Keyring::create(&path, b"fixture passphrase").unwrap();
        let a = first.import_public("First", &[1; 32]).unwrap();
        let mut stale = Keyring::open(&path, b"fixture passphrase").unwrap();
        let b = first.import_public("Second", &[2; 32]).unwrap();
        assert!(stale.import_public("Not saved", &[3; 32]).is_err());
        assert_eq!(stale.accounts().unwrap().len(), 1);
        first.select(b).unwrap();
        first.rename(a, "Renamed").unwrap();
        assert!(matches!(
            first.import_public("Duplicate", &[1; 32]),
            Err(Error::Duplicate)
        ));
        drop(first);
        drop(stale);
        let reopened = Keyring::open(&path, b"fixture passphrase").unwrap();
        let accounts = reopened.accounts().unwrap();
        assert_eq!(accounts.len(), 2);
        assert!(accounts[1].selected);
        assert_eq!(accounts[0].label, "Renamed");
        assert_eq!(reopened.signing_key(a).unwrap().value(), &[1; 32]);
        assert!(Keyring::open(&path, b"wrong password").is_err());
    }
}
