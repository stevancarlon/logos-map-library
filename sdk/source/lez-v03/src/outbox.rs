// SPDX-License-Identifier: MIT OR Apache-2.0
//! Version-specific encrypted outbox. Always persist before the first broadcast.
use crate::{
    AccountId,
    accounts::{AccountInfo, Accounts, Permission, Secret},
    transfer::{NativeReader, NativeTransfer, PreparedTransfer, Wallet},
};
use crate::{Error, Node, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use lee_v03::PublicTransaction;
use logos_wallet_policy::principal::Principal;
use logos_wallet_policy::{Grant, Policy};
use logos_wallet_store::Store;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::BTreeSet, path::Path};
use zeroize::Zeroizing;
const FORMAT: &str = "logos-lez-v03-native-outbox-v1";
const MAX_WIRE: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    PreparedOrSubmissionUnknown,
    Submitted,
    Uncertain,
    IncludedBySequencer,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Status {
    pub id: String,
    pub hash: String,
    pub endpoint: String,
    pub state: State,
    pub last_checked_at: Option<u64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    id: String,
    principal: Principal,
    endpoint: String,
    transaction: Vec<u8>,
    state: State,
    last_checked_at: Option<u64>,
}
impl Record {
    fn decode(&self) -> Result<PublicTransaction> {
        decode_transfer(&self.transaction)
    }
    fn status(&self) -> Result<Status> {
        Ok(Status {
            id: self.id.clone(),
            hash: hex::encode(self.decode()?.hash()),
            endpoint: self.endpoint.clone(),
            state: self.state.clone(),
            last_checked_at: self.last_checked_at,
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Book {
    format: String,
    records: Vec<Record>,
    #[serde(default)]
    accounts: Accounts,
    #[serde(default)]
    private: private_store::PrivateBook,
}
fn decode_transfer(bytes: &[u8]) -> Result<PublicTransaction> {
    if bytes.is_empty() || bytes.len() > MAX_WIRE {
        return Err(Error::Invalid("invalid saved transaction length"));
    }
    let tx: PublicTransaction = borsh::from_slice(bytes)
        .map_err(|_| Error::Invalid("invalid v0.3 transaction encoding"))?;
    let message = &tx.message;
    let signers = tx.witness_set.signatures_and_public_keys();
    let native = lee_core_v03::native_token::NATIVE_TOKEN_PROGRAM_ID;
    let token = token_core_v03::token_account_id();
    if (message.program_account_id != native && message.program_account_id != token)
        || message.shard_selectors.len() != 2
        || message.nonces.len() != 1
        || signers.len() != 1
        || message
            .shard_selectors
            .iter()
            .any(|selector| selector.program_account_id != message.program_account_id)
        || message.shard_selectors[0].account_id == message.shard_selectors[1].account_id
        || lee_v03::AccountId::from(&signers[0].1) != message.shard_selectors[0].account_id
        || !tx.witness_set.is_valid_for(message)
        || message.fee.is_none()
        || !lee_v03::is_fee_authorized(message, &tx.witness_set)
    {
        return Err(Error::Invalid(
            "saved transaction is not an authorized v0.3 public transfer",
        ));
    }
    if message.program_account_id == native {
        let instruction: lee_core_v03::native_token::Instruction =
            borsh::from_slice(&message.instruction_data)
                .map_err(|_| Error::Invalid("invalid native instruction"))?;
        if matches!(
            instruction,
            lee_core_v03::native_token::Instruction::Transfer { amount: 0 }
        ) {
            return Err(Error::Invalid("zero native transfer"));
        }
    } else {
        let instruction: token_core_v03::Instruction = borsh::from_slice(&message.instruction_data)
            .map_err(|_| Error::Invalid("invalid token instruction"))?;
        let token_core_v03::Instruction::Transfer {
            amount_to_transfer,
            descriptor,
        } = instruction
        else {
            return Err(Error::Invalid(
                "outbox only accepts approved token transfers",
            ));
        };
        if amount_to_transfer == 0
            || (descriptor.kind == token_core_v03::TokenKind::NftPrintedCopy
                && amount_to_transfer != 1)
            || message
                .shard_selectors
                .iter()
                .any(|s| s.account_id == descriptor.definition_id)
        {
            return Err(Error::Invalid(
                "invalid token transfer amount or definition",
            ));
        }
    }
    Ok(tx)
}
fn validate(book: &Book) -> Result<()> {
    book.accounts.policy()?;
    book.private.validate()?;
    if book.format != FORMAT || book.records.len() > 256 {
        return Err(Error::Invalid("unsupported or full v0.3 outbox"));
    }
    let mut ids = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    for record in &book.records {
        record.principal.validate()?;
        Node::new(&record.endpoint)?;
        if record.endpoint.len() > 2048
            || record.id.len() != 32
            || !record
                .id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !ids.insert(&record.id)
            || !hashes.insert((&record.endpoint, record.decode()?.hash()))
            || (record.state == State::IncludedBySequencer && record.last_checked_at.is_none())
        {
            return Err(Error::Invalid("invalid or duplicate outbox record"));
        }
    }
    Ok(())
}
pub trait SubmissionNode {
    fn endpoint(&self) -> &str;
    fn broadcast(&self, transaction: &PublicTransaction) -> Result<[u8; 32]>;
    fn observed(&self, transaction: &PublicTransaction) -> Result<bool>;
}
impl SubmissionNode for Node {
    fn endpoint(&self) -> &str {
        &self.endpoint
    }
    fn broadcast(&self, transaction: &PublicTransaction) -> Result<[u8; 32]> {
        let bytes = borsh::to_vec(transaction)
            .map_err(|_| Error::Invalid("cannot encode signed transaction"))?;
        decode_transfer(&bytes)?;
        // Canonical LeeTransaction::Public Borsh tag followed by upstream public transaction.
        let mut wire = vec![0];
        wire.extend(bytes);
        let returned: String = self.read("sendTransaction", json!([STANDARD.encode(wire)]))?;
        let hash: [u8; 32] = hex::decode(returned)
            .map_err(|_| Error::Invalid("invalid submission hash"))?
            .try_into()
            .map_err(|_| Error::Invalid("invalid submission hash length"))?;
        if hash != transaction.hash() {
            return Err(Error::Invalid("submission hash mismatch"));
        }
        Ok(hash)
    }
    fn observed(&self, transaction: &PublicTransaction) -> Result<bool> {
        let value: Option<(String, u64)> =
            self.read("getTransaction", json!([hex::encode(transaction.hash())]))?;
        let Some((encoded, _block)) = value else {
            return Ok(false);
        };
        if encoded.len() > (MAX_WIRE + 1) * 4 / 3 + 4 {
            return Err(Error::Invalid("oversized confirmed transaction"));
        }
        let wire = STANDARD
            .decode(encoded)
            .map_err(|_| Error::Invalid("invalid confirmed transaction encoding"))?;
        if wire.first() != Some(&0) {
            return Err(Error::Invalid("confirmation is not a public transaction"));
        }
        let returned = decode_transfer(&wire[1..])?;
        if returned != *transaction || returned.hash() != transaction.hash() {
            return Err(Error::Invalid(
                "confirmation differs from saved transaction",
            ));
        }
        Ok(true)
    }
}
pub struct Outbox {
    store: Store,
    password: Zeroizing<Vec<u8>>,
    revision: u64,
    book: Book,
    policy: Policy,
}
impl Outbox {
    pub fn create(path: &Path, password: &[u8]) -> Result<Self> {
        if password.is_empty() || password.len() > 4096 {
            return Err(Error::Invalid("invalid password length"));
        }
        let book = Book {
            format: FORMAT.into(),
            records: vec![],
            accounts: Accounts::default(),
            private: private_store::PrivateBook::default(),
        };
        let payload = Zeroizing::new(serde_json::to_vec(&book)?);
        let store = Store::create(path, password, &payload)?;
        Ok(Self {
            store,
            password: Zeroizing::new(password.to_vec()),
            revision: 0,
            book,
            policy: Policy::default(),
        })
    }
    pub fn open(path: &Path, password: &[u8]) -> Result<Self> {
        if password.is_empty() || password.len() > 4096 {
            return Err(Error::Invalid("invalid password length"));
        }
        let store = Store::open(path)?;
        let snapshot = store.load(password)?;
        let book: Book = serde_json::from_slice(&snapshot.payload)?;
        validate(&book)?;
        let policy = book.accounts.policy()?;
        Ok(Self {
            store,
            password: Zeroizing::new(password.to_vec()),
            revision: snapshot.revision,
            book,
            policy,
        })
    }
    fn current(&self) -> Result<()> {
        if self.store.load(&self.password)?.revision != self.revision {
            return Err(logos_wallet_store::Error::Conflict.into());
        }
        Ok(())
    }
    fn commit(&mut self, book: Book) -> Result<()> {
        validate(&book)?;
        let policy = book.accounts.policy()?;
        let payload = Zeroizing::new(serde_json::to_vec(&book)?);
        self.revision = self.store.save(&self.password, self.revision, &payload)?;
        self.book = book;
        // Durable changes invalidate pending reviews; reviews never survive restart.
        self.replace_permissions(policy)?;
        Ok(())
    }
    fn replace_permissions(&mut self, replacement: Policy) -> Result<()> {
        // Revoke pending reviews while retaining this session's monotonically
        // increasing prompt counter. Replacing Policy with Default would let a
        // stale owner decision ID refer to a new, different review.
        let previous: Vec<_> = self.policy.grants().map(|(app, _)| app.clone()).collect();
        for app in previous {
            self.policy.revoke(&app);
        }
        for (app, grant) in replacement.grants() {
            self.policy.set_grant(app.clone(), grant.clone())?;
        }
        Ok(())
    }
    /// Owner channel only. Never expose all accounts/labels through dApp IPC.
    pub fn owner_accounts(&self) -> Result<Vec<AccountInfo>> {
        self.current()?;
        self.book.accounts.infos()
    }
    /// Owner channel only. Explicit public-key import; never decodes a v0.2 wallet.
    pub fn owner_import_public(
        &mut self,
        key: Zeroizing<[u8; 32]>,
        label: &str,
    ) -> Result<AccountId> {
        self.current()?;
        let secret = Secret {
            key: *key,
            label: label.into(),
        };
        let id = secret.identity()?;
        let mut book = self.book.clone();
        book.accounts.selected.get_or_insert(id);
        book.accounts.secrets.push(secret);
        self.commit(book)?;
        Ok(id)
    }
    pub fn owner_create_public(&mut self, label: &str) -> Result<AccountId> {
        let key = lee_v03::PrivateKey::new_os_random();
        self.owner_import_public(Zeroizing::new(*key.value()), label)
    }
    pub fn owner_select(&mut self, account: AccountId) -> Result<()> {
        self.current()?;
        self.book.accounts.secret(account)?;
        let mut book = self.book.clone();
        book.accounts.selected = Some(account);
        self.commit(book)
    }
    pub fn owner_rename(&mut self, account: AccountId, label: &str) -> Result<()> {
        self.current()?;
        let mut book = self.book.clone();
        let index = book
            .accounts
            .secrets
            .iter()
            .position(|s| s.identity().ok() == Some(account))
            .ok_or(Error::Invalid("account not found"))?;
        book.accounts.secrets[index].label = label.into();
        self.commit(book)
    }
    /// Explicit owner consent only; caller identity comes from authenticated dispatch.
    pub fn owner_set_grant(&mut self, principal: &Principal, grant: Option<Grant>) -> Result<()> {
        self.current()?;
        principal.validate()?;
        let mut book = self.book.clone();
        book.accounts
            .permissions
            .retain(|p| &p.principal != principal);
        if let Some(grant) = grant {
            book.accounts.permissions.push(Permission {
                principal: principal.clone(),
                grant,
            });
        }
        self.commit(book)
    }
    /// One authenticated revision check for the complete owner-only snapshot.
    pub fn owner_snapshot(&self) -> Result<serde_json::Value> {
        self.current()?;
        let grants:Vec<_>=self.book.accounts.permissions.iter().map(|p|json!({"principal":p.principal,
            "accounts":p.grant.accounts.iter().copied().map(AccountId::from_bytes).collect::<Vec<_>>(),"scopes":p.grant.scopes})).collect();
        let activity: Vec<_> = self
            .book
            .records
            .iter()
            .map(|r| Ok(json!({"principal":r.principal,"transaction":r.status()?})))
            .collect::<Result<_>>()?;
        Ok(json!({"accounts":self.book.accounts.infos()?,"grants":grants,"activity":activity}))
    }
    pub fn owner_reconcile(
        &mut self,
        id: &str,
        node: &impl SubmissionNode,
        now: u64,
    ) -> Result<Status> {
        self.current()?;
        let principal = self
            .book
            .records
            .iter()
            .find(|r| r.id == id)
            .ok_or(Error::Invalid("saved transaction not found"))?
            .principal
            .clone();
        self.reconcile(&principal, id, node, now)
    }
    /// Trusted session only. Authorizes the wallet owner's own selected key for
    /// this unlocked session; no persistent app permission is granted.
    pub(crate) fn owner_allow_account(
        &mut self,
        principal: &Principal,
        account: AccountId,
    ) -> Result<()> {
        self.current()?;
        self.book.accounts.secret(account)?;
        self.policy.set_grant(
            principal.policy_id()?,
            Grant {
                accounts: [account.bytes()].into(),
                scopes: [logos_wallet_policy::Scope::Transactions].into(),
            },
        )?;
        Ok(())
    }
    /// Only the authenticated caller's grant is disclosed on the app channel.
    pub fn grant_for(&self, principal: &Principal) -> Result<Option<Grant>> {
        self.current()?;
        principal.validate()?;
        Ok(self
            .book
            .accounts
            .permissions
            .iter()
            .find(|p| &p.principal == principal)
            .map(|p| p.grant.clone()))
    }
    /// Check a narrow read permission before any network access. Account listing,
    /// signing and proof permissions never imply balance or NFT access.
    pub(crate) fn require_read_scope(
        &self,
        principal: &Principal,
        account: AccountId,
        scope: logos_wallet_policy::Scope,
    ) -> Result<()> {
        self.current()?;
        if !matches!(
            scope,
            logos_wallet_policy::Scope::PublicBalance | logos_wallet_policy::Scope::NftEnumeration
        ) || !self
            .policy
            .permitted(&principal.policy_id()?, scope, Some(account.bytes()))
        {
            return Err(Error::Invalid("account read permission denied"));
        }
        self.book.accounts.secret(account)?;
        Ok(())
    }
    pub fn accounts_for(&self, principal: &Principal) -> Result<Vec<AccountId>> {
        self.current()?;
        Ok(self
            .policy
            .accounts(&principal.policy_id()?)?
            .into_iter()
            .map(AccountId::from_bytes)
            .collect())
    }
    /// Trusted terminal owner only. This session-only permission is never saved
    /// as a dApp grant; cancelling the following review leaves SQLite unchanged.
    pub fn owner_allow_local_cli_account(&mut self, account: AccountId) -> Result<()> {
        self.current()?;
        self.book.accounts.secret(account)?;
        self.policy.set_grant(
            Principal::LocalCli.policy_id()?,
            Grant {
                accounts: [account.bytes()].into(),
                scopes: [logos_wallet_policy::Scope::Transactions].into(),
            },
        )?;
        Ok(())
    }
    pub fn prepare_native(
        &mut self,
        principal: &Principal,
        wallet: &Wallet<impl NativeReader>,
        transfer: NativeTransfer,
        now: u64,
    ) -> Result<PreparedTransfer> {
        self.current()?;
        if !self.policy.permitted(
            &principal.policy_id()?,
            logos_wallet_policy::Scope::Transactions,
            Some(transfer.from.bytes()),
        ) {
            return Err(Error::Invalid("transaction permission denied"));
        }
        self.book.accounts.secret(transfer.from)?;
        wallet.prepare_native(&mut self.policy, &principal.policy_id()?, transfer, now)
    }
    /// Trusted owner approval route; never publish this as a dApp-callable method.
    pub fn owner_decide(&mut self, prompt: u64, approved: bool, now: u64) -> Result<()> {
        self.current()?;
        Ok(self.policy.decide(prompt, approved, now)?)
    }
    pub fn execute_native(
        &mut self,
        principal: &Principal,
        id: &str,
        wallet: &Wallet<impl NativeReader>,
        node: &impl SubmissionNode,
        prepared: &PreparedTransfer,
        now: u64,
    ) -> Result<Status> {
        self.current()?;
        if wallet.endpoint() != node.endpoint() {
            return Err(Error::Invalid("submission endpoint differs from approval"));
        }
        let key = self.book.accounts.secret(prepared.sender())?.signer()?;
        let signed = wallet.sign_approved(
            &mut self.policy,
            &principal.policy_id()?,
            prepared,
            &key,
            now,
        )?;
        self.submit_new(principal, id, node, signed)
    }
    pub fn prepare_token(
        &mut self,
        principal: &Principal,
        wallet: &crate::token::TokenWallet<impl crate::token::TokenReader>,
        transfer: crate::token::TokenTransfer,
        now: u64,
    ) -> Result<crate::token::PreparedTokenTransfer> {
        self.current()?;
        let app = principal.policy_id()?;
        if !self.policy.permitted(
            &app,
            logos_wallet_policy::Scope::Transactions,
            Some(transfer.from.bytes()),
        ) {
            return Err(Error::Invalid("transaction permission denied"));
        }
        self.book.accounts.secret(transfer.from)?;
        wallet.prepare(&mut self.policy, &app, transfer, now)
    }
    pub fn execute_token(
        &mut self,
        principal: &Principal,
        id: &str,
        wallet: &crate::token::TokenWallet<impl crate::token::TokenReader>,
        node: &impl SubmissionNode,
        prepared: &crate::token::PreparedTokenTransfer,
        now: u64,
    ) -> Result<Status> {
        self.current()?;
        if wallet.endpoint() != node.endpoint() {
            return Err(Error::Invalid(
                "token submission endpoint differs from approval",
            ));
        }
        let key = self.book.accounts.secret(prepared.sender())?.signer()?;
        let signed = wallet.sign_approved(
            &mut self.policy,
            &principal.policy_id()?,
            prepared,
            &key,
            now,
        )?;
        self.submit_new(principal, id, node, signed)
    }
    pub fn owner_rotate_password(
        &mut self,
        current_password: &[u8],
        new_password: &[u8],
    ) -> Result<()> {
        if new_password.is_empty() || new_password.len() > 4096 {
            return Err(Error::Invalid("invalid password length"));
        }
        self.current()?;
        self.revision =
            self.store
                .rotate_password(current_password, new_password, self.revision)?;
        self.password = Zeroizing::new(new_password.to_vec());
        self.replace_permissions(self.book.accounts.policy()?)?;
        Ok(())
    }
    pub fn status(&self, principal: &Principal, id: &str) -> Result<Status> {
        self.status_optional(principal, id)?
            .ok_or(Error::Invalid("request not found for this caller"))
    }
    pub fn status_optional(&self, principal: &Principal, id: &str) -> Result<Option<Status>> {
        self.current()?;
        principal.validate()?;
        self.book
            .records
            .iter()
            .find(|r| r.id == id && &r.principal == principal)
            .map(Record::status)
            .transpose()
    }
    /// Owner network/session changes cancel reviews without rewriting the file.
    pub fn owner_cancel_pending(&mut self) -> Result<()> {
        self.current()?;
        self.replace_permissions(self.book.accounts.policy()?)
    }
    /// Caller-scoped recovery IDs, including records saved before a process died.
    pub fn activity_for(&self, principal: &Principal) -> Result<Vec<Status>> {
        principal.validate()?;
        self.current()?;
        self.book
            .records
            .iter()
            .filter(|r| &r.principal == principal)
            .map(Record::status)
            .collect()
    }
    /// Trusted executor only: call with a transaction returned by sign_approved.
    /// Repeated IDs or hashes are rejected, including after restart or timeout.
    pub fn submit_new(
        &mut self,
        principal: &Principal,
        id: &str,
        node: &impl SubmissionNode,
        transaction: PublicTransaction,
    ) -> Result<Status> {
        self.current()?;
        let record = Record {
            id: id.into(),
            principal: principal.clone(),
            endpoint: node.endpoint().into(),
            transaction: borsh::to_vec(&transaction)
                .map_err(|_| Error::Invalid("cannot encode transaction"))?,
            state: State::PreparedOrSubmissionUnknown,
            last_checked_at: None,
        };
        let mut book = self.book.clone();
        book.records.push(record);
        self.commit(book)?;
        let state = match node.broadcast(&transaction) {
            Ok(hash) if hash == transaction.hash() => State::Submitted,
            _ => State::Uncertain,
        };
        let mut book = self.book.clone();
        book.records
            .last_mut()
            .ok_or(Error::Invalid("missing saved request"))?
            .state = state;
        self.commit(book)?;
        self.status(principal, id)
    }
    /// Reads the original saved hash only; never broadcasts or signs a retry.
    pub fn reconcile(
        &mut self,
        principal: &Principal,
        id: &str,
        node: &impl SubmissionNode,
        now: u64,
    ) -> Result<Status> {
        self.current()?;
        let index = self
            .book
            .records
            .iter()
            .position(|r| r.id == id && &r.principal == principal)
            .ok_or(Error::Invalid("request not found for this caller"))?;
        let record = &self.book.records[index];
        if record.endpoint != node.endpoint() {
            return Err(Error::Invalid(
                "selected endpoint differs from saved transaction",
            ));
        }
        let included = node.observed(&record.decode()?)?;
        let mut book = self.book.clone();
        book.records[index].state = if included {
            State::IncludedBySequencer
        } else {
            State::Uncertain
        };
        book.records[index].last_checked_at = Some(now);
        self.commit(book)?;
        self.status(principal, id)
    }
}

#[cfg(test)]
mod token_wire_tests {
    use super::*;
    use lee_core_v03::account::ProgramShardSelector;
    use lee_v03::{
        PrivateKey, PublicKey,
        fees::FeeDeclaration,
        public_transaction::{Message, WitnessSet},
    };
    use token_core_v03::{Instruction, TokenDescriptor, TokenKind};
    fn signed(instruction: Instruction) -> PublicTransaction {
        let key = PrivateKey::try_new([1; 32]).unwrap();
        let from = lee_v03::AccountId::from(&PublicKey::new_from_private_key(&key));
        let program = token_core_v03::token_account_id();
        let message = Message::try_new_with_fees(
            program,
            vec![from, lee_v03::AccountId::new([2; 32])]
                .into_iter()
                .map(|account_id| ProgramShardSelector {
                    account_id,
                    program_account_id: program,
                })
                .collect(),
            vec![0u128.into()],
            instruction,
            FeeDeclaration::new(from, 8_000_000, 7, 100_000_000),
        )
        .unwrap();
        let witness = WitnessSet::for_message(&message, &[&key]);
        PublicTransaction::new(message, witness)
    }
    fn transfer(kind: TokenKind, amount: u128) -> Instruction {
        Instruction::Transfer {
            amount_to_transfer: amount,
            descriptor: TokenDescriptor {
                definition_id: lee_v03::AccountId::new([5; 32]),
                kind,
            },
        }
    }
    fn valid(tx: &PublicTransaction) -> bool {
        decode_transfer(&borsh::to_vec(tx).unwrap()).is_ok()
    }
    #[test]
    fn outbox_accepts_only_signed_reference_transfer_variants() {
        for kind in [
            TokenKind::Fungible,
            TokenKind::NftMaster,
            TokenKind::NftPrintedCopy,
        ] {
            assert!(valid(&signed(transfer(kind, 1))));
            assert!(!valid(&signed(transfer(kind, 0))));
        }
        assert!(!valid(&signed(transfer(TokenKind::NftPrintedCopy, 2))));
        assert!(!valid(&signed(Instruction::Mint { amount_to_mint: 1 })));
        let key = PrivateKey::try_new([1; 32]).unwrap();
        for invalid in 0..4 {
            let mut tx = signed(transfer(TokenKind::Fungible, 1));
            match invalid {
                0 => {
                    tx.message.shard_selectors[0].program_account_id =
                        lee_core_v03::native_token::NATIVE_TOKEN_PROGRAM_ID
                }
                1 => tx.message.fee.as_mut().unwrap().payer = lee_v03::AccountId::new([9; 32]),
                2 => tx.message.program_account_id = lee_v03::AccountId::new([8; 32]),
                _ => tx.message.shard_selectors[1].account_id = lee_v03::AccountId::new([5; 32]),
            }
            tx.witness_set = WitnessSet::for_message(&tx.message, &[&key]);
            assert!(!valid(&tx));
        }
    }
}

#[path = "private_store.rs"]
mod private_store;
