// SPDX-License-Identifier: MIT OR Apache-2.0
//! Private records share the existing encrypted v0.3 SQLite payload. No legacy
//! files or openings are imported, and no proof result is saved as confirmed.
use super::*;
use crate::shielded::{
    self, Direction, NativeOperation, Prepared, PrivateIdentity, PrivateSubmissionNode,
    ShieldedReader,
};
use lee_core_v03::{Commitment, account::Account};
use lee_v03::PrivacyPreservingTransaction;
use logos_wallet_policy::Scope;
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrivateBook {
    accounts: Vec<PrivateAccount>,
    records: Vec<PrivateRecord>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateAccount {
    identity: PrivateIdentity,
    label: String,
    endpoint: Option<String>,
    state: Option<Account>,
    pending: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateRecord {
    id: String,
    account: AccountId,
    endpoint: String,
    wire: String,
    pending_state: Account,
    state: State,
    last_checked_at: Option<u64>,
    opening_confirmed: bool,
}
fn request_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl PrivateRecord {
    fn transaction(&self) -> Result<PrivacyPreservingTransaction> {
        if self.wire.len() > shielded::MAX_PRIVATE_WIRE * 4 / 3 + 4 {
            return Err(Error::Invalid("oversized saved private transaction"));
        }
        let bytes = STANDARD
            .decode(&self.wire)
            .map_err(|_| Error::Invalid("invalid saved private wire"))?;
        borsh::from_slice(&bytes).map_err(|_| Error::Invalid("invalid saved private transaction"))
    }
    fn status(&self) -> Result<serde_json::Value> {
        Ok(
            json!({"transaction":Status{id:self.id.clone(),hash:hex::encode(self.transaction()?.hash()),endpoint:self.endpoint.clone(),state:self.state.clone(),last_checked_at:self.last_checked_at},"private_account":self.account,"opening_confirmed":self.opening_confirmed,"execution_outcome":if self.opening_confirmed{"private_commitment_observed"}else{"unknown"}}),
        )
    }
}
impl PrivateBook {
    pub(super) fn validate(&self) -> Result<()> {
        if self.accounts.len() > 32 || self.records.len() > 64 {
            return Err(Error::Invalid("private wallet capacity exceeded"));
        }
        let mut accounts = BTreeSet::new();
        let mut records = BTreeSet::new();
        let mut hashes = BTreeSet::new();
        for account in &self.accounts {
            if account.label.trim().is_empty()
                || account.label.len() > 100
                || account.label.chars().any(char::is_control)
                || !accounts.insert(account.identity.account())
                || account.state.is_some() && account.endpoint.is_none()
            {
                return Err(Error::Invalid("invalid private account record"));
            }
            if let Some(endpoint) = &account.endpoint {
                if endpoint.len() > 2048 {
                    return Err(Error::Invalid("private endpoint too long"));
                }
                Node::new(endpoint)?;
            }
        }
        for record in &self.records {
            let tx = record.transaction()?;
            shielded::verify_signed(&tx)?;
            if !request_id(&record.id)
                || !records.insert(&record.id)
                || !hashes.insert((&record.endpoint, tx.hash()))
                || !accounts.contains(&record.account)
                || tx.message.private_actions.len() != 7
                || tx.message.public_actions.len() != 1
                || record.endpoint.len() > 2048
                || (record.opening_confirmed
                    && (record.state != State::IncludedBySequencer
                        || record.last_checked_at.is_none()))
            {
                return Err(Error::Invalid("invalid private outbox record"));
            }
            Node::new(&record.endpoint)?;
            let commitment = Commitment::new(
                &lee_v03::AccountId::new(record.account.bytes()),
                &record.pending_state,
            );
            if tx
                .message
                .commitments()
                .iter()
                .filter(|c| **c == commitment)
                .count()
                != 1
            {
                return Err(Error::Invalid(
                    "saved private opening is not committed by transaction",
                ));
            }
            let account = self
                .accounts
                .iter()
                .find(|a| a.identity.account() == record.account)
                .ok_or(Error::Invalid("private key not found"))?;
            if account.endpoint.as_deref() != Some(&record.endpoint)
                || (!record.opening_confirmed && account.pending.as_deref() != Some(&record.id))
            {
                return Err(Error::Invalid("private pending record/account mismatch"));
            }
        }
        for account in &self.accounts {
            if let Some(id) = &account.pending
                && !self.records.iter().any(|r| {
                    &r.id == id && r.account == account.identity.account() && !r.opening_confirmed
                })
            {
                return Err(Error::Invalid("private pending transaction not found"));
            }
        }
        Ok(())
    }
}
impl Outbox {
    /// Trusted owner API, not exposed to a dApp request body.
    pub fn owner_import_private(
        &mut self,
        identity: PrivateIdentity,
        label: &str,
    ) -> Result<AccountId> {
        self.current()?;
        let id = identity.account();
        let mut book = self.book.clone();
        book.private.accounts.push(PrivateAccount {
            identity,
            label: label.into(),
            endpoint: None,
            state: None,
            pending: None,
        });
        self.commit(book)?;
        Ok(id)
    }
    pub fn owner_create_private(&mut self, label: &str) -> Result<AccountId> {
        self.owner_import_private(PrivateIdentity::generate()?, label)
    }
    pub fn owner_private_accounts(&self) -> Result<Vec<serde_json::Value>> {
        self.current()?;
        self.book.private.accounts.iter().map(|a|Ok(json!({"account":a.identity.account(),"label":a.label,"privacy":"private","endpoint":a.endpoint,"initialized":a.state.is_some(),"pending":a.pending,"native_balance":a.state.as_ref().map(|s|s.data.native_balance().map(|n|n.to_string())).transpose().map_err(|_|Error::Invalid("invalid stored private native balance"))?}))).collect()
    }
    pub fn owner_prepare_private_native(
        &mut self,
        node: &impl ShieldedReader,
        account: AccountId,
        operation: NativeOperation,
        now: u64,
    ) -> Result<Prepared> {
        self.current()?;
        let private = self
            .book
            .private
            .accounts
            .iter()
            .find(|a| a.identity.account() == account)
            .ok_or(Error::Invalid("private account not found"))?;
        if private.pending.is_some()
            || private
                .endpoint
                .as_deref()
                .is_some_and(|e| e != node.endpoint())
        {
            return Err(Error::Invalid(
                "private account has pending work or belongs to another endpoint",
            ));
        }
        let mut accounts = BTreeSet::from([account.bytes()]);
        if operation.direction == Direction::Deposit {
            self.book.accounts.secret(operation.public_account)?;
            accounts.insert(operation.public_account.bytes());
        }
        self.policy.set_grant(
            Principal::LocalCli.policy_id()?,
            Grant {
                accounts,
                scopes: [Scope::Transactions].into(),
            },
        )?;
        shielded::prepare_native(
            &mut self.policy,
            &Principal::LocalCli.policy_id()?,
            node,
            &private.identity,
            private.state.as_ref(),
            operation,
            now,
        )
    }
    pub fn owner_execute_private_native(
        &mut self,
        id: &str,
        node: &impl PrivateSubmissionNode,
        prepared: &Prepared,
        now: u64,
    ) -> Result<serde_json::Value> {
        self.current()?;
        if !request_id(id)
            || self.book.private.records.iter().any(|r| r.id == id)
            || self.book.records.iter().any(|r| r.id == id)
        {
            return Err(Error::Invalid("invalid or reused private request ID"));
        }
        let index = self
            .book
            .private
            .accounts
            .iter()
            .position(|a| a.identity.account() == prepared.private_account())
            .ok_or(Error::Invalid("private account not found"))?;
        let account = &self.book.private.accounts[index];
        if account.pending.is_some()
            || account
                .endpoint
                .as_deref()
                .is_some_and(|e| e != prepared.endpoint())
        {
            return Err(Error::Invalid("private account state changed"));
        }
        let key = if prepared.operation().direction == Direction::Deposit {
            Some(
                self.book
                    .accounts
                    .secret(prepared.operation().public_account)?
                    .signer()?,
            )
        } else {
            None
        };
        let proven = shielded::prove_native(
            &mut self.policy,
            &Principal::LocalCli.policy_id()?,
            node,
            &account.identity,
            key.as_ref(),
            prepared,
            now,
        )?;
        // Another process may have changed the vault or public state while proving.
        self.current()?;
        prepared.check_public(node)?;
        let bytes = borsh::to_vec(proven.transaction())
            .map_err(|_| Error::Invalid("cannot save private transaction"))?;
        if bytes.len() > shielded::MAX_PRIVATE_WIRE {
            return Err(Error::Invalid(
                "private transaction exceeds wallet wire limit",
            ));
        }
        let mut book = self.book.clone();
        book.private.accounts[index].pending = Some(id.into());
        book.private.accounts[index].endpoint = Some(proven.endpoint().into());
        book.private.records.push(PrivateRecord {
            id: id.into(),
            account: proven.private_account(),
            endpoint: proven.endpoint().into(),
            wire: STANDARD.encode(bytes),
            pending_state: proven.pending_state().clone(),
            state: State::PreparedOrSubmissionUnknown,
            last_checked_at: None,
            opening_confirmed: false,
        });
        self.commit(book)?;
        // Exactly one attempt. Failed or mismatched acknowledgement stays uncertain.
        let acknowledged = node
            .broadcast_private(proven.transaction())
            .is_ok_and(|hash| hash == proven.transaction().hash());
        let mut book = self.book.clone();
        book.private
            .records
            .last_mut()
            .ok_or(Error::Invalid("private outbox disappeared"))?
            .state = if acknowledged {
            State::Submitted
        } else {
            State::Uncertain
        };
        self.commit(book)?;
        self.owner_private_status(id)
    }
    pub fn owner_private_status(&self, id: &str) -> Result<serde_json::Value> {
        self.current()?;
        self.book
            .private
            .records
            .iter()
            .find(|r| r.id == id)
            .ok_or(Error::Invalid("private request not found"))?
            .status()
    }
    pub fn owner_private_activity(&self) -> Result<Vec<serde_json::Value>> {
        self.current()?;
        self.book
            .private
            .records
            .iter()
            .map(PrivateRecord::status)
            .collect()
    }
    /// Reconcile exact wire and requested commitment without signing or resending.
    pub fn owner_reconcile_private(
        &mut self,
        id: &str,
        node: &impl PrivateSubmissionNode,
        now: u64,
    ) -> Result<serde_json::Value> {
        self.current()?;
        let index = self
            .book
            .private
            .records
            .iter()
            .position(|r| r.id == id)
            .ok_or(Error::Invalid("private request not found"))?;
        let record = &self.book.private.records[index];
        if record.endpoint != node.endpoint() {
            return Err(Error::Invalid(
                "private reconciliation endpoint differs from saved network",
            ));
        }
        let included = node.observed_private(&record.transaction()?)?;
        let commitment = Commitment::new(
            &lee_v03::AccountId::new(record.account.bytes()),
            &record.pending_state,
        );
        let confirmed = if included {
            let (proofs, root) = node.proofs_and_root(&[commitment])?;
            shielded::validate_memberships(&[commitment], &proofs, root)?;
            proofs[0].is_some()
        } else {
            false
        };
        let mut book = self.book.clone();
        let record = &mut book.private.records[index];
        record.state = if included {
            State::IncludedBySequencer
        } else {
            State::Uncertain
        };
        record.last_checked_at = Some(now);
        if confirmed && !record.opening_confirmed {
            let account = book
                .private
                .accounts
                .iter_mut()
                .find(|a| a.identity.account() == record.account)
                .ok_or(Error::Invalid("private account not found"))?;
            if account.pending.as_deref() != Some(id) {
                return Err(Error::Invalid(
                    "private opening changed during reconciliation",
                ));
            }
            account.state = Some(record.pending_state.clone());
            account.pending = None;
            record.opening_confirmed = true;
        }
        // Never roll a confirmed opening back due to a later missing/lagging observation.
        if record.opening_confirmed {
            record.state = State::IncludedBySequencer;
        }
        self.commit(book)?;
        self.owner_private_status(id)
    }
}
