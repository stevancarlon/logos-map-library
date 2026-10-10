// SPDX-License-Identifier: MIT OR Apache-2.0
//! Ephemeral access requests; durable grants are committed by the owner session.
use crate::{Error, Result};
use logos_wallet_policy::{Grant, Scope, principal::Principal};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Serialize)]
pub struct Prompt {
    pub id: String,
    pub principal: Principal,
    pub scopes: BTreeSet<Scope>,
    pub expires_at: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum State {
    Pending,
    Rejected,
    Approved { grant: Grant },
}
struct Entry {
    prompt: Prompt,
    state: State,
}
#[derive(Default)]
pub(crate) struct Requests {
    entries: BTreeMap<String, Entry>,
}
impl Requests {
    pub fn prune(&mut self, now: u64) {
        self.entries.retain(|_, e| e.prompt.expires_at > now);
    }
    pub fn clear(&mut self) {
        self.entries.clear();
    }
    pub fn remove_principal(&mut self, principal: &Principal) {
        self.entries.retain(|_, e| &e.prompt.principal != principal);
    }
    pub fn request(
        &mut self,
        caller: &Principal,
        scopes: BTreeSet<Scope>,
        now: u64,
    ) -> Result<String> {
        caller.validate()?;
        self.prune(now);
        if matches!(caller, Principal::LocalCli)
            || scopes.is_empty()
            || !scopes.iter().all(|s| {
                matches!(
                    s,
                    Scope::Accounts
                        | Scope::Transactions
                        | Scope::PublicBalance
                        | Scope::NftEnumeration
                )
            })
        {
            return Err(Error::Invalid("unsupported v0.3 access scopes"));
        }
        if self.entries.len() >= 64
            || self
                .entries
                .values()
                .filter(|e| &e.prompt.principal == caller)
                .count()
                >= 8
        {
            return Err(Error::Invalid("access request limit reached"));
        }
        let expires_at = now
            .checked_add(300)
            .ok_or(Error::Invalid("invalid clock"))?;
        let mut nonce = [0; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Invalid("OS randomness unavailable"))?;
        let id = hex::encode(nonce);
        if self.entries.contains_key(&id) {
            return Err(Error::Invalid("duplicate access request ID"));
        }
        self.entries.insert(
            id.clone(),
            Entry {
                prompt: Prompt {
                    id: id.clone(),
                    principal: caller.clone(),
                    scopes,
                    expires_at,
                },
                state: State::Pending,
            },
        );
        Ok(id)
    }
    pub fn prompts(&mut self, now: u64) -> Vec<Prompt> {
        self.prune(now);
        self.entries
            .values()
            .filter(|e| e.state == State::Pending)
            .map(|e| e.prompt.clone())
            .collect()
    }
    pub fn status(&mut self, caller: &Principal, id: &str, now: u64) -> Result<State> {
        self.prune(now);
        self.entries
            .get(id)
            .filter(|e| &e.prompt.principal == caller)
            .map(|e| e.state.clone())
            .ok_or(Error::Invalid("access request missing or expired"))
    }
    /// Pure validation. Persistence must succeed before complete() is called.
    pub fn selection(&mut self, id: &str, grant: Option<&Grant>, now: u64) -> Result<Principal> {
        self.prune(now);
        let e = self
            .entries
            .get(id)
            .filter(|e| e.state == State::Pending)
            .ok_or(Error::Invalid("access request missing or expired"))?;
        if let Some(grant) = grant
            && (grant.accounts.is_empty()
                || grant.scopes.is_empty()
                || !grant.scopes.is_subset(&e.prompt.scopes))
        {
            return Err(Error::Invalid("access selection exceeds request"));
        }
        Ok(e.prompt.principal.clone())
    }
    pub fn complete(&mut self, id: &str, grant: Option<Grant>) {
        if let Some(entry) = self.entries.get_mut(id) {
            entry.state = grant.map_or(State::Rejected, |grant| State::Approved { grant });
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn app(n: usize) -> Principal {
        Principal::Module {
            name: format!("app{n}"),
            instance: String::new(),
        }
    }
    fn scopes() -> BTreeSet<Scope> {
        BTreeSet::from([Scope::Accounts])
    }
    #[test]
    fn expiry_identity_selection_replay_and_supported_scopes() {
        let mut requests = Requests::default();
        let id = requests.request(&app(1), scopes(), 10).unwrap();
        assert!(requests.status(&app(2), &id, 11).is_err());
        assert!(
            requests
                .selection(
                    &id,
                    Some(&Grant {
                        accounts: BTreeSet::from([[1; 32]]),
                        scopes: BTreeSet::from([Scope::Transactions])
                    }),
                    11
                )
                .is_err()
        );
        assert!(
            requests
                .request(&app(1), BTreeSet::from([Scope::CollectionProof]), 11)
                .is_err()
        );
        assert_eq!(requests.selection(&id, None, 11).unwrap(), app(1));
        requests.complete(&id, None);
        assert!(matches!(
            requests.status(&app(1), &id, 12).unwrap(),
            State::Rejected
        ));
        assert!(requests.selection(&id, None, 12).is_err());
        assert!(requests.status(&app(1), &id, 310).is_err());
        assert!(requests.request(&app(1), scopes(), u64::MAX).is_err());
        let id = requests.request(&app(1), scopes(), 400).unwrap();
        requests.clear();
        assert!(requests.selection(&id, None, 400).is_err());
    }
    #[test]
    fn per_caller_and_global_limits_expire_without_starving_other_callers() {
        let mut requests = Requests::default();
        for app_id in 0..8 {
            for _ in 0..8 {
                requests.request(&app(app_id), scopes(), 10).unwrap();
            }
        }
        assert!(requests.request(&app(9), scopes(), 10).is_err());
        requests.remove_principal(&app(0));
        for _ in 0..8 {
            requests.request(&app(9), scopes(), 10).unwrap();
        }
        assert!(requests.request(&app(9), scopes(), 10).is_err());
        assert!(requests.request(&app(9), scopes(), 310).is_ok());
        assert_eq!(requests.prompts(310).len(), 1);
    }
}
