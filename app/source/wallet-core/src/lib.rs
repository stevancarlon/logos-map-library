// SPDX-License-Identifier: MIT OR Apache-2.0
//! Wallet-side permission and approval state machine, with no signing keys.
//! The embedding wallet must authenticate AppId via its IPC channel; never accept
//! a dApp's self-reported identity as the channel identity. UI authorization calls
//! belong exclusively on the trusted wallet channel, never the provider channel.
pub mod principal;
pub mod vault;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct AppId(pub String);
pub type AccountId = [u8; 32];
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum Scope {
    Accounts,
    PublicBalance,
    PrivateBalance,
    NftEnumeration,
    Transactions,
    CollectionProof,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Grant {
    pub accounts: BTreeSet<AccountId>,
    pub scopes: BTreeSet<Scope>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Effect {
    InitializeNativeAccount {
        program: [u8; 32],
    },
    NativeVaultClaim {
        amount: String,
        vault: AccountId,
    },
    NativeTransfer {
        amount: String,
        destination: AccountId,
    },
    TokenTransfer {
        asset: AccountId,
        amount: String,
        destination: AccountId,
    },
    NftTransfer {
        collection: AccountId,
        token: AccountId,
        destination: AccountId,
    },
    UnlimitedApproval {
        asset: AccountId,
        spender: AccountId,
    },
    ContractCall {
        program: [u8; 32],
        instruction: String,
        explanation: String,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Transaction {
    pub account: AccountId,
    /// Digest binding the canonical chain message (including nonce) and wallet network context.
    pub message_hash: [u8; 32],
    /// Must be decoded independently by the wallet, never copied from a dApp's label.
    pub effects: Vec<Effect>,
    pub network: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProofRequest {
    pub collection: AccountId,
    pub challenge: [u8; 32],
    pub audience: String,
    pub network: String,
    pub expires_at: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Request {
    Transaction(Transaction),
    CollectionProof(ProofRequest),
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Prompt {
    pub id: u64,
    pub app: AppId,
    pub request: Request,
    pub expires_at: u64,
}
struct Pending {
    prompt: Prompt,
    approved: bool,
}
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum Error {
    #[error("Permission denied")]
    PermissionDenied,
    #[error("Invalid request")]
    Invalid,
    #[error("Approval missing, expired, or revoked")]
    ApprovalRequired,
    #[error("Request queue full")]
    QueueFull,
}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Default)]
pub struct Policy {
    grants: BTreeMap<AppId, Grant>,
    pending: BTreeMap<u64, Pending>,
    next: u64,
}
impl Policy {
    /// Trusted wallet UI only: called after an explicit account/scope selection.
    pub fn set_grant(&mut self, app: AppId, grant: Grant) -> Result<()> {
        if app.0.is_empty()
            || app.0.len() > 256
            || grant.scopes.is_empty()
            || grant.accounts.len() > 100
        {
            return Err(Error::Invalid);
        }
        if grant.scopes.iter().any(|s| *s != Scope::CollectionProof) && grant.accounts.is_empty() {
            return Err(Error::Invalid);
        }
        self.revoke(&app);
        self.grants.insert(app, grant);
        Ok(())
    }
    pub fn revoke(&mut self, app: &AppId) {
        self.grants.remove(app);
        self.pending.retain(|_, p| &p.prompt.app != app);
    }
    /// Trusted wallet UI only. Revokes one capability and its pending approvals;
    /// unrelated capabilities and independently approved requests remain intact.
    pub fn revoke_scope(&mut self, app: &AppId, scope: Scope) {
        if let Some(grant) = self.grants.get_mut(app) {
            grant.scopes.remove(&scope);
            if grant.scopes.is_empty() {
                self.grants.remove(app);
            }
        }
        self.pending.retain(|_, pending| {
            &pending.prompt.app != app
                || match &pending.prompt.request {
                    Request::Transaction(_) => scope != Scope::Transactions,
                    Request::CollectionProof(_) => scope != Scope::CollectionProof,
                }
        });
    }
    /// Removes access to one account, including unconsumed transaction approvals.
    /// Standalone proof permission has no account access and is not changed here.
    pub fn revoke_account(&mut self, app: &AppId, account: AccountId) {
        if let Some(grant) = self.grants.get_mut(app) {
            grant.accounts.remove(&account);
        }
        self.pending.retain(|_, pending| {
            &pending.prompt.app != app || !matches!(&pending.prompt.request, Request::Transaction(t) if t.account == account)
        });
    }
    /// Trusted wallet settings only; never expose all apps' grants through provider IPC.
    pub fn grants(&self) -> impl Iterator<Item = (&AppId, &Grant)> {
        self.grants.iter()
    }
    pub fn permitted(&self, app: &AppId, scope: Scope, account: Option<AccountId>) -> bool {
        self.grants.get(app).is_some_and(|g| {
            g.scopes.contains(&scope) && account.is_none_or(|a| g.accounts.contains(&a))
        })
    }
    /// Proof-only permissions never return selected accounts, even if stored locally.
    pub fn accounts(&self, app: &AppId) -> Result<Vec<AccountId>> {
        if !self.permitted(app, Scope::Accounts, None) {
            return Err(Error::PermissionDenied);
        }
        Ok(self
            .grants
            .get(app)
            .ok_or(Error::PermissionDenied)?
            .accounts
            .iter()
            .copied()
            .collect())
    }
    fn allowed(&self, app: &AppId, r: &Request) -> bool {
        match r {
            Request::Transaction(t) => self.permitted(app, Scope::Transactions, Some(t.account)),
            Request::CollectionProof(_) => self.permitted(app, Scope::CollectionProof, None),
        }
    }
    pub fn request(&mut self, app: &AppId, request: Request, now: u64) -> Result<Prompt> {
        self.pending.retain(|_, p| p.prompt.expires_at > now);
        if self.pending.len() >= 128 {
            return Err(Error::QueueFull);
        }
        if !self.allowed(app, &request) {
            return Err(Error::PermissionDenied);
        }
        let mut expires_at = now.checked_add(300).ok_or(Error::Invalid)?;
        match &request {
            Request::Transaction(t) => {
                if t.network.is_empty()
                    || t.network.len() > 256
                    || t.message_hash == [0; 32]
                    || t.effects.is_empty()
                    || t.effects.len() > 64
                {
                    return Err(Error::Invalid);
                }
                for effect in &t.effects {
                    match effect {
                        Effect::NativeTransfer { amount, .. }
                        | Effect::NativeVaultClaim { amount, .. }
                        | Effect::TokenTransfer { amount, .. } => {
                            if amount.is_empty()
                                || amount.len() > 39
                                || !amount.bytes().all(|b| b.is_ascii_digit())
                                || amount.parse::<u128>().ok().filter(|n| *n > 0).is_none()
                            {
                                return Err(Error::Invalid);
                            }
                        }
                        Effect::ContractCall {
                            instruction,
                            explanation,
                            ..
                        } if instruction.trim().is_empty()
                            || instruction.len() > 128
                            || explanation.trim().is_empty()
                            || explanation.len() > 4096 =>
                        {
                            return Err(Error::Invalid);
                        }
                        _ => {}
                    }
                }
            }
            Request::CollectionProof(p) => {
                if p.collection == [0; 32]
                    || p.challenge == [0; 32]
                    || p.audience.trim().is_empty()
                    || p.audience.len() > 256
                    || p.network.trim().is_empty()
                    || p.network.len() > 256
                    || p.expires_at <= now
                {
                    return Err(Error::Invalid);
                }
                expires_at = expires_at.min(p.expires_at);
            }
        }
        self.next = self.next.checked_add(1).ok_or(Error::QueueFull)?;
        let prompt = Prompt {
            id: self.next,
            app: app.clone(),
            request,
            expires_at,
        };
        self.pending.insert(
            prompt.id,
            Pending {
                prompt: prompt.clone(),
                approved: false,
            },
        );
        Ok(prompt)
    }
    /// Trusted UI only. Approval authorizes precisely the immutable displayed request.
    pub fn decide(&mut self, id: u64, approved: bool, now: u64) -> Result<()> {
        let pending = self.pending.get_mut(&id).ok_or(Error::ApprovalRequired)?;
        if pending.prompt.expires_at <= now {
            self.pending.remove(&id);
            return Err(Error::ApprovalRequired);
        }
        if !approved {
            self.pending.remove(&id);
        } else {
            pending.approved = true;
        }
        Ok(())
    }
    /// Wallet executor only; consumes approval once, before calling the signer/prover.
    /// If execution fails, a fresh user approval is required for another attempt.
    pub fn consume(
        &mut self,
        app: &AppId,
        id: u64,
        request: &Request,
        now: u64,
    ) -> Result<Request> {
        let p = self.pending.get(&id).ok_or(Error::ApprovalRequired)?;
        if &p.prompt.app != app
            || &p.prompt.request != request
            || !p.approved
            || p.prompt.expires_at <= now
            || !self.allowed(app, request)
        {
            return Err(Error::ApprovalRequired);
        }
        Ok(self
            .pending
            .remove(&id)
            .ok_or(Error::ApprovalRequired)?
            .prompt
            .request)
    }
}
/// Domain-separated public proof context. Contains no account or token identifier.
/// This digest is an input to a future real membership circuit, NOT a membership proof.
pub fn proof_context(app: &AppId, request: &ProofRequest) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"logos.nft.collection-proof.context.v1\0");
    for bytes in [
        app.0.as_bytes(),
        &request.collection,
        &request.challenge,
        request.audience.as_bytes(),
        request.network.as_bytes(),
        &request.expires_at.to_le_bytes(),
    ] {
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn app() -> AppId {
        AppId("fixture.app".into())
    }
    fn proof() -> Request {
        Request::CollectionProof(ProofRequest {
            collection: [1; 32],
            challenge: [2; 32],
            audience: "fixture.verifier".into(),
            network: "local-test".into(),
            expires_at: 200,
        })
    }
    fn policy() -> Policy {
        let mut p = Policy::default();
        p.set_grant(
            app(),
            Grant {
                accounts: BTreeSet::new(),
                scopes: BTreeSet::from([Scope::CollectionProof]),
            },
        )
        .unwrap();
        p
    }
    #[test]
    fn proof_only_never_exposes_accounts_or_balances() {
        let p = policy();
        assert!(p.accounts(&app()).is_err());
        for scope in [
            Scope::PublicBalance,
            Scope::PrivateBalance,
            Scope::NftEnumeration,
            Scope::Transactions,
        ] {
            assert!(!p.permitted(&app(), scope, None));
        }
    }
    #[test]
    fn proof_always_requires_explicit_one_time_approval() {
        let mut p = policy();
        let prompt = p.request(&app(), proof(), 100).unwrap();
        assert!(p.consume(&app(), prompt.id, &proof(), 100).is_err());
        p.decide(prompt.id, true, 100).unwrap();
        p.consume(&app(), prompt.id, &proof(), 101).unwrap();
        assert!(p.consume(&app(), prompt.id, &proof(), 102).is_err());
    }
    #[test]
    fn approval_cannot_cross_app_context_or_expiry() {
        let mut p = policy();
        let prompt = p.request(&app(), proof(), 100).unwrap();
        p.decide(prompt.id, true, 100).unwrap();
        assert!(
            p.consume(&AppId("attacker".into()), prompt.id, &proof(), 100)
                .is_err()
        );
        let Request::CollectionProof(mut changed) = proof() else {
            panic!()
        };
        changed.challenge = [3; 32];
        assert!(
            p.consume(&app(), prompt.id, &Request::CollectionProof(changed), 100)
                .is_err()
        );
        assert!(p.consume(&app(), prompt.id, &proof(), 200).is_err());
    }
    #[test]
    fn revocation_invalidates_pending_approvals() {
        let mut p = policy();
        let prompt = p.request(&app(), proof(), 100).unwrap();
        p.decide(prompt.id, true, 100).unwrap();
        p.revoke(&app());
        assert!(p.consume(&app(), prompt.id, &proof(), 101).is_err());
    }
    #[test]
    fn capability_revocation_is_independent_and_invalidates_old_approval() {
        let mut p = policy();
        p.set_grant(
            app(),
            Grant {
                accounts: BTreeSet::from([[7; 32]]),
                scopes: BTreeSet::from([
                    Scope::Accounts,
                    Scope::CollectionProof,
                    Scope::PublicBalance,
                ]),
            },
        )
        .unwrap();
        let prompt = p.request(&app(), proof(), 100).unwrap();
        p.decide(prompt.id, true, 100).unwrap();
        p.revoke_scope(&app(), Scope::Accounts);
        assert!(p.accounts(&app()).is_err());
        assert!(p.permitted(&app(), Scope::PublicBalance, Some([7; 32])));
        p.consume(&app(), prompt.id, &proof(), 101).unwrap();
        let prompt = p.request(&app(), proof(), 102).unwrap();
        p.decide(prompt.id, true, 102).unwrap();
        p.revoke_scope(&app(), Scope::CollectionProof);
        assert!(p.consume(&app(), prompt.id, &proof(), 103).is_err());
        assert!(p.permitted(&app(), Scope::PublicBalance, Some([7; 32])));
        p.revoke_account(&app(), [7; 32]);
        assert!(!p.permitted(&app(), Scope::PublicBalance, Some([7; 32])));
    }
    #[test]
    fn rejection_removes_request() {
        let mut p = policy();
        let prompt = p.request(&app(), proof(), 100).unwrap();
        p.decide(prompt.id, false, 100).unwrap();
        assert!(p.decide(prompt.id, true, 101).is_err());
    }
    #[test]
    fn account_revocation_cancels_only_that_accounts_transaction() {
        let mut p = policy();
        p.set_grant(
            app(),
            Grant {
                accounts: BTreeSet::from([[7; 32], [8; 32]]),
                scopes: BTreeSet::from([
                    Scope::Accounts,
                    Scope::Transactions,
                    Scope::CollectionProof,
                ]),
            },
        )
        .unwrap();
        let transaction = Request::Transaction(Transaction {
            account: [7; 32],
            message_hash: [9; 32],
            network: "fixture".into(),
            effects: vec![Effect::NativeTransfer {
                amount: "1".into(),
                destination: [8; 32],
            }],
        });
        let tx_prompt = p.request(&app(), transaction.clone(), 100).unwrap();
        let proof_prompt = p.request(&app(), proof(), 100).unwrap();
        p.decide(tx_prompt.id, true, 100).unwrap();
        p.decide(proof_prompt.id, true, 100).unwrap();
        p.revoke_account(&app(), [7; 32]);
        assert!(p.consume(&app(), tx_prompt.id, &transaction, 101).is_err());
        assert_eq!(p.accounts(&app()).unwrap(), vec![[8; 32]]);
        assert!(p.permitted(&app(), Scope::Transactions, Some([8; 32])));
        p.consume(&app(), proof_prompt.id, &proof(), 101).unwrap();
    }
    #[test]
    fn context_binds_app_audience_network_and_challenge() {
        let Request::CollectionProof(r) = proof() else {
            panic!()
        };
        let h = proof_context(&app(), &r);
        let mut next = r.clone();
        next.audience.push('x');
        assert_ne!(h, proof_context(&app(), &next));
        assert_ne!(h, proof_context(&AppId("other".into()), &r));
        next = r.clone();
        next.network.push('x');
        assert_ne!(h, proof_context(&app(), &next));
        next = r;
        next.challenge = [3; 32];
        assert_ne!(h, proof_context(&app(), &next));
    }
}
