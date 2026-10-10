// SPDX-License-Identifier: MIT OR Apache-2.0
//! Encrypted public account records. Only the trusted wallet owns this module's store API.
use crate::{AccountId, Error, Result};
use lee_v03::{PrivateKey, PublicKey};
use logos_wallet_policy::{Grant, Policy, principal::Principal};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use zeroize::Zeroize;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Secret {
    pub label: String,
    pub key: [u8; 32],
}
impl Drop for Secret {
    fn drop(&mut self) {
        self.key.zeroize();
        self.label.zeroize();
    }
}
impl Secret {
    pub fn identity(&self) -> Result<AccountId> {
        let key = self.signer()?;
        Ok(AccountId::from_bytes(
            *lee_v03::AccountId::from(&PublicKey::new_from_private_key(&key)).value(),
        ))
    }
    pub fn signer(&self) -> Result<PrivateKey> {
        PrivateKey::try_new(self.key).map_err(|_| Error::Invalid("invalid v0.3 public key"))
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Permission {
    pub principal: Principal,
    pub grant: Grant,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Accounts {
    pub selected: Option<AccountId>,
    pub secrets: Vec<Secret>,
    pub permissions: Vec<Permission>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccountInfo {
    pub account: AccountId,
    pub label: String,
    pub selected: bool,
}
impl Accounts {
    pub fn policy(&self) -> Result<Policy> {
        if self.secrets.len() > 256 || self.permissions.len() > 256 {
            return Err(Error::Invalid("v0.3 account or permission limit exceeded"));
        }
        let mut ids = BTreeSet::new();
        for secret in &self.secrets {
            if secret.label.trim().is_empty()
                || secret.label.len() > 100
                || secret.label.chars().any(char::is_control)
                || !ids.insert(secret.identity()?.bytes())
            {
                return Err(Error::Invalid("invalid or duplicate public account"));
            }
        }
        if self.selected.is_some_and(|id| !ids.contains(&id.bytes()))
            || (self.selected.is_none() && !ids.is_empty())
        {
            return Err(Error::Invalid("invalid selected account"));
        }
        let mut policy = Policy::default();
        let mut principals = BTreeSet::new();
        for permission in &self.permissions {
            let app = permission.principal.policy_id()?;
            if !principals.insert(app.clone()) || !permission.grant.accounts.is_subset(&ids) {
                return Err(Error::Invalid("invalid or duplicate permission"));
            }
            policy.set_grant(app, permission.grant.clone())?;
        }
        Ok(policy)
    }
    pub fn infos(&self) -> Result<Vec<AccountInfo>> {
        self.secrets
            .iter()
            .map(|s| {
                let account = s.identity()?;
                Ok(AccountInfo {
                    account,
                    label: s.label.clone(),
                    selected: Some(account) == self.selected,
                })
            })
            .collect()
    }
    pub fn secret(&self, id: AccountId) -> Result<&Secret> {
        for secret in &self.secrets {
            if secret.identity()? == id {
                return Ok(secret);
            }
        }
        Err(Error::Invalid("v0.3 public account not found"))
    }
}
