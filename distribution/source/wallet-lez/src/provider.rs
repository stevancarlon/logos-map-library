// SPDX-License-Identifier: MIT OR Apache-2.0
//! Wallet-side provider session. The Basecamp adapter supplies Principal from
//! ambient dispatch. Trusted UI methods here must never be exposed in dApp LIDL.
pub mod native;
pub mod transactions;
use crate::keyring::{AccountInfo, Keyring, ProviderGrant};
use crate::{NativeWallet, Node, token::HoldingView};
use logos_registry_sdk::HttpNode;
use logos_wallet_policy::{AccountId, Grant, Policy, Scope, principal::Principal};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use transactions::{TransactionProposal, TransactionRecord};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Policy(#[from] logos_wallet_policy::Error),
    #[error(transparent)]
    Keyring(#[from] crate::keyring::Error),
    #[error(transparent)]
    Chain(#[from] crate::Error),
    #[error("Configure the wallet's sequencer before reading balances")]
    NetworkNotConfigured,
    #[error("Program source information changed; request a new review before approving")]
    SourceChanged,
    #[error(
        "This operation requires a public account; private operations use a separate permission and shielded flow"
    )]
    NotPublic,
    #[error("Access request missing or expired")]
    MissingRequest,
    #[error("Access request limit reached")]
    QueueFull,
    #[error("Invalid permission selection")]
    InvalidSelection,
    #[error("Invalid provider request")]
    InvalidRequest,
    #[error("Secure request identifier unavailable")]
    Randomness,
}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Debug, Serialize)]
pub struct AccessPrompt {
    pub id: String,
    pub principal: Principal,
    pub scopes: BTreeSet<Scope>,
    pub expires_at: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AccessState {
    Pending,
    Approved { scopes: BTreeSet<Scope> },
    Rejected,
}
struct AccessRequest {
    prompt: AccessPrompt,
    state: AccessState,
}
/// Untrusted dApp request body. Identity and trusted approval operations are
/// deliberately absent. The adapter supplies authenticated Principal separately.
#[derive(Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
enum DappRequest {
    RequestAccess { scopes: BTreeSet<Scope> },
    AccessStatus { id: String },
    Accounts {},
    ProposeTransaction { proposal: TransactionProposal },
    TransactionStatus { id: String },
    RefreshTransaction { id: String },
    NativeBalance { account: lee::AccountId },
    FungibleBalance { holding: lee::AccountId },
    NftHolding { holding: lee::AccountId },
}
pub struct Provider {
    keyring: Keyring,
    policy: Policy,
    access: BTreeMap<String, AccessRequest>,
    network: Option<NativeWallet<HttpNode>>,
    transactions: BTreeMap<String, TransactionRecord>,
    source_review: Option<logos_registry_sdk::verification::ReviewConfig>,
}
impl Provider {
    pub fn unlocked(keyring: Keyring) -> Result<Self> {
        let policy = keyring.provider_policy()?;
        Ok(Self {
            keyring,
            policy,
            access: BTreeMap::new(),
            network: None,
            transactions: BTreeMap::new(),
            source_review: None,
        })
    }
    /// Trusted local registry/receipt selection only. Invalidate old prompts so
    /// no decision uses source information from a different configuration.
    pub fn configure_source_review(
        &mut self,
        config: Option<logos_registry_sdk::verification::ReviewConfig>,
    ) {
        self.cancel_transactions(None);
        self.source_review = config;
    }
    /// Trusted wallet configuration only. dApps cannot supply a node URL in
    /// a read request. No network call is made until a permitted read executes.
    pub fn configure_network(&mut self, endpoint: &str) -> Result<()> {
        let wallet = NativeWallet::connect(endpoint)?;
        if self
            .network
            .as_ref()
            .is_none_or(|old| old.endpoint != wallet.endpoint)
        {
            self.cancel_transactions(None);
        }
        self.network = Some(wallet);
        Ok(())
    }
    fn ensure_public_access(
        &self,
        caller: &Principal,
        scope: Scope,
        account: lee::AccountId,
    ) -> Result<()> {
        if !self.permitted(caller, scope, Some(*account.value()))? {
            return Err(logos_wallet_policy::Error::PermissionDenied.into());
        }
        if !self
            .keyring
            .accounts()?
            .iter()
            .any(|info| info.account == account && info.privacy == "public")
        {
            return Err(Error::NotPublic);
        }
        Ok(())
    }
    pub fn native_balance<N: Node>(
        &self,
        caller: &Principal,
        wallet: &NativeWallet<N>,
        account: lee::AccountId,
    ) -> Result<serde_json::Value> {
        self.ensure_public_access(caller, Scope::PublicBalance, account)?;
        let value = wallet.public_balance(&self.policy, &caller.policy_id()?, *account.value())?;
        Ok(
            serde_json::json!({"account": account, "base_units": value.to_string(), "network": wallet.endpoint, "source": "configured_sequencer"}),
        )
    }
    pub fn fungible_balance<N: Node>(
        &self,
        caller: &Principal,
        wallet: &NativeWallet<N>,
        holding: lee::AccountId,
    ) -> Result<serde_json::Value> {
        self.ensure_public_access(caller, Scope::PublicBalance, holding)?;
        let (definition, value) =
            wallet.fungible_balance(&self.policy, &caller.policy_id()?, *holding.value())?;
        Ok(
            serde_json::json!({"holding": holding, "definition": lee::AccountId::new(definition), "token_base_units": value.to_string(), "network": wallet.endpoint, "source": "configured_sequencer"}),
        )
    }
    pub fn nft_holding<N: Node>(
        &self,
        caller: &Principal,
        wallet: &NativeWallet<N>,
        holding: lee::AccountId,
    ) -> Result<serde_json::Value> {
        self.ensure_public_access(caller, Scope::NftEnumeration, holding)?;
        let value =
            wallet.public_nft_holding(&self.policy, &caller.policy_id()?, *holding.value())?;
        Ok(
            serde_json::json!({"holding": holding, "state": HoldingView::from(value), "network": wallet.endpoint, "source": "configured_sequencer"}),
        )
    }
    /// The only JSON dispatcher intended for the dApp-facing module method.
    /// The caller argument is captured by the transport adapter, never parsed
    /// out of `payload`. Approval, revocation, keys and other apps' grants have
    /// no routes here. Bodies are bounded before parsing.
    pub fn dispatch(
        &mut self,
        caller: &Principal,
        payload: &str,
        now: u64,
    ) -> Result<serde_json::Value> {
        caller.validate()?;
        if payload.len() > 8192 {
            return Err(Error::InvalidRequest);
        }
        let request: DappRequest =
            serde_json::from_str(payload).map_err(|_| Error::InvalidRequest)?;
        match request {
            DappRequest::RequestAccess { scopes } => {
                Ok(serde_json::json!({"id": self.request_access(caller, scopes, now)?}))
            }
            DappRequest::AccessStatus { id } => {
                if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(Error::InvalidRequest);
                }
                serde_json::to_value(self.access_status(caller, &id, now)?)
                    .map_err(|_| Error::InvalidRequest)
            }
            DappRequest::ProposeTransaction { proposal } => {
                let wallet = self.network.take().ok_or(Error::NetworkNotConfigured)?;
                let result = self.propose_transaction(caller, &wallet, proposal, now);
                self.network = Some(wallet);
                Ok(serde_json::json!({"id": result?}))
            }
            DappRequest::TransactionStatus { id } => {
                if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(Error::InvalidRequest);
                }
                serde_json::to_value(self.transaction_status(caller, &id, now)?)
                    .map_err(|_| Error::InvalidRequest)
            }
            DappRequest::RefreshTransaction { id } => {
                if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(Error::InvalidRequest);
                }
                let endpoint = &self
                    .network
                    .as_ref()
                    .ok_or(Error::NetworkNotConfigured)?
                    .endpoint;
                let submission = self
                    .keyring
                    .reconcile_public_submission(caller, &id, endpoint, now)?;
                serde_json::to_value(transactions::TransactionState::Submission { submission })
                    .map_err(|_| Error::InvalidRequest)
            }
            DappRequest::NativeBalance { account } => self.native_balance(
                caller,
                self.network.as_ref().ok_or(Error::NetworkNotConfigured)?,
                account,
            ),
            DappRequest::FungibleBalance { holding } => self.fungible_balance(
                caller,
                self.network.as_ref().ok_or(Error::NetworkNotConfigured)?,
                holding,
            ),
            DappRequest::NftHolding { holding } => self.nft_holding(
                caller,
                self.network.as_ref().ok_or(Error::NetworkNotConfigured)?,
                holding,
            ),
            DappRequest::Accounts {} => {
                serde_json::to_value(self.accounts(caller)?).map_err(|_| Error::InvalidRequest)
            }
        }
    }
    fn prune(&mut self, now: u64) {
        self.access.retain(|_, entry| entry.prompt.expires_at > now);
    }
    /// dApp capability: requests permission, grants nothing. A collection-proof
    /// request cannot be bundled with any account-related permission.
    pub fn request_access(
        &mut self,
        caller: &Principal,
        scopes: BTreeSet<Scope>,
        now: u64,
    ) -> Result<String> {
        caller.validate()?;
        self.prune(now);
        if scopes.is_empty() || (scopes.contains(&Scope::CollectionProof) && scopes.len() != 1) {
            return Err(Error::InvalidSelection);
        }
        if self.access.len() >= 128 {
            return Err(Error::QueueFull);
        }
        let expires_at = now.checked_add(300).ok_or(Error::InvalidSelection)?;
        let mut nonce = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Randomness)?;
        let id: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        if self.access.contains_key(&id) {
            return Err(Error::Randomness);
        }
        self.access.insert(
            id.clone(),
            AccessRequest {
                prompt: AccessPrompt {
                    id: id.clone(),
                    principal: caller.clone(),
                    scopes,
                    expires_at,
                },
                state: AccessState::Pending,
            },
        );
        Ok(id)
    }
    /// dApp capability: status is visible only to its authenticated requester.
    pub fn access_status(&mut self, caller: &Principal, id: &str, now: u64) -> Result<AccessState> {
        self.prune(now);
        let entry = self
            .access
            .get(id)
            .filter(|entry| &entry.prompt.principal == caller)
            .ok_or(Error::MissingRequest)?;
        if matches!(entry.state, AccessState::Approved { .. }) {
            self.keyring.ensure_current()?;
        }
        Ok(entry.state.clone())
    }
    /// dApp capability: proof-only grants cannot enumerate account IDs/labels.
    pub fn accounts(&self, caller: &Principal) -> Result<Vec<AccountInfo>> {
        let allowed: BTreeSet<_> = self
            .policy
            .accounts(&caller.policy_id()?)?
            .into_iter()
            .collect();
        self.keyring.ensure_current()?;
        Ok(self
            .keyring
            .accounts()?
            .into_iter()
            .filter(|info| allowed.contains(info.account.value()))
            .collect())
    }
    /// Trusted wallet UI only. Not an IPC method on the provider contract.
    pub fn access_prompts(&mut self, now: u64) -> Vec<AccessPrompt> {
        self.prune(now);
        self.access
            .values()
            .filter(|entry| entry.state == AccessState::Pending)
            .map(|entry| entry.prompt.clone())
            .collect()
    }
    /// Trusted wallet UI only. A user can approve a subset of requested scopes.
    /// Account-scope updates replace prior account selections; the UI must show
    /// that change. Proof permission is independent and is preserved separately.
    /// Saving fails atomically if another wallet session changed the database.
    pub fn decide_access(&mut self, id: &str, selection: Option<Grant>, now: u64) -> Result<()> {
        self.prune(now);
        let entry = self
            .access
            .get_mut(id)
            .filter(|entry| entry.state == AccessState::Pending)
            .ok_or(Error::MissingRequest)?;
        let Some(grant) = selection else {
            entry.state = AccessState::Rejected;
            return Ok(());
        };
        if grant.scopes.is_empty()
            || !grant.scopes.is_subset(&entry.prompt.scopes)
            || (grant.scopes.contains(&Scope::CollectionProof) && !grant.accounts.is_empty())
        {
            return Err(Error::InvalidSelection);
        }
        let approved_scopes = grant.scopes.clone();
        let existing = self
            .keyring
            .provider_grants()
            .iter()
            .find(|record| record.principal == entry.prompt.principal);
        let grant = if grant.scopes == BTreeSet::from([Scope::CollectionProof]) {
            let mut combined = existing.map(|record| record.grant.clone()).unwrap_or(grant);
            combined.scopes.insert(Scope::CollectionProof);
            combined
        } else {
            let mut combined = grant;
            if existing.is_some_and(|record| record.grant.scopes.contains(&Scope::CollectionProof))
            {
                combined.scopes.insert(Scope::CollectionProof);
            }
            combined
        };
        let app = entry.prompt.principal.policy_id()?;
        // Validate before persistence. The same validated input then updates the
        // live policy, invalidating old transaction/proof approvals for this app.
        let mut validation = Policy::default();
        validation.set_grant(app.clone(), grant.clone())?;
        self.keyring
            .set_provider_grant(entry.prompt.principal.clone(), grant.clone())?;
        self.policy.set_grant(app, grant.clone())?;
        entry.state = AccessState::Approved {
            scopes: approved_scopes,
        };
        let principal = entry.prompt.principal.clone();
        self.cancel_transactions(Some(&principal));
        Ok(())
    }
    /// Trusted wallet settings only; never disclose other apps' permissions.
    pub fn grants(&self) -> &[ProviderGrant] {
        self.keyring.provider_grants()
    }
    pub fn revoke(&mut self, caller: &Principal) -> Result<()> {
        let app = caller.policy_id()?;
        self.keyring.revoke_provider_grant(caller)?;
        self.policy.revoke(&app);
        self.cancel_transactions(Some(caller));
        self.access
            .retain(|_, entry| &entry.prompt.principal != caller);
        Ok(())
    }
    /// Trusted settings only. Independent scope revocation persists first, then
    /// invalidates pending requests and the corresponding live authorization.
    pub fn revoke_scope(&mut self, caller: &Principal, scope: Scope) -> Result<()> {
        self.keyring.ensure_current()?;
        let app = caller.policy_id()?;
        let Some(record) = self
            .keyring
            .provider_grants()
            .iter()
            .find(|g| &g.principal == caller)
        else {
            return Ok(());
        };
        let mut grant = record.grant.clone();
        grant.scopes.remove(&scope);
        if grant.scopes.is_empty() {
            return self.revoke(caller);
        }
        if grant.scopes == BTreeSet::from([Scope::CollectionProof]) {
            grant.accounts.clear();
        }
        self.keyring.set_provider_grant(caller.clone(), grant)?;
        let transactions_revoked = scope == Scope::Transactions;
        self.policy.revoke_scope(&app, scope);
        if transactions_revoked {
            self.cancel_transactions(Some(caller));
        }
        self.access
            .retain(|_, entry| &entry.prompt.principal != caller);
        Ok(())
    }
    /// Trusted settings only. Removing the last account preserves proof-only access.
    pub fn revoke_account(&mut self, caller: &Principal, account: AccountId) -> Result<()> {
        self.keyring.ensure_current()?;
        let app = caller.policy_id()?;
        let Some(record) = self
            .keyring
            .provider_grants()
            .iter()
            .find(|g| &g.principal == caller)
        else {
            return Ok(());
        };
        let mut grant = record.grant.clone();
        let old_scopes = grant.scopes.clone();
        if !grant.accounts.remove(&account) {
            return Ok(());
        }
        if grant.accounts.is_empty() {
            grant
                .scopes
                .retain(|scope| *scope == Scope::CollectionProof);
            if grant.scopes.is_empty() {
                return self.revoke(caller);
            }
        }
        self.keyring
            .set_provider_grant(caller.clone(), grant.clone())?;
        self.cancel_account_transactions(caller, lee::AccountId::new(account));
        self.policy.revoke_account(&app, account);
        if grant.accounts.is_empty() {
            // No account-scoped authority may remain after its final account is removed.
            for scope in old_scopes {
                if scope != Scope::CollectionProof {
                    self.policy.revoke_scope(&app, scope);
                }
            }
        }
        self.access
            .retain(|_, entry| &entry.prompt.principal != caller);
        Ok(())
    }
    pub fn permitted(
        &self,
        caller: &Principal,
        scope: Scope,
        account: Option<AccountId>,
    ) -> Result<bool> {
        let permitted = self.policy.permitted(&caller.policy_id()?, scope, account);
        if permitted {
            self.keyring.ensure_current()?;
        }
        Ok(permitted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PASSWORD: &[u8] = b"provider fixture password";
    fn caller(name: &str) -> Principal {
        Principal::Module {
            name: name.into(),
            instance: String::new(),
        }
    }
    fn grant(account: Option<AccountId>, scopes: &[Scope]) -> Grant {
        Grant {
            accounts: account.into_iter().collect(),
            scopes: scopes.iter().cloned().collect(),
        }
    }
    #[test]
    fn balance_reads_check_permissions_privacy_and_lossless_output() {
        use logos_registry_sdk::AccountReader;
        use std::cell::Cell;
        struct ReadNode {
            accounts: BTreeMap<lee::AccountId, lee::Account>,
            calls: Cell<usize>,
        }
        impl AccountReader for ReadNode {
            fn account(&self, id: lee::AccountId) -> logos_registry_sdk::Result<lee::Account> {
                self.calls.set(self.calls.get() + 1);
                self.accounts
                    .get(&id)
                    .cloned()
                    .ok_or_else(|| logos_registry_sdk::Error::Invalid("Missing fixture".into()))
            }
        }
        impl Node for ReadNode {
            fn submit_transaction(
                &self,
                _: &common::transaction::LeeTransaction,
            ) -> logos_registry_sdk::Result<common::HashType> {
                panic!("read methods must not submit transactions")
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let mut ring = Keyring::create(&dir.path().join("balances.sqlite"), PASSWORD).unwrap();
        let native = ring.import_public("Native", &[1; 32]).unwrap();
        let fungible = ring.import_public("Fungible", &[2; 32]).unwrap();
        let nft = ring.import_public("NFT", &[3; 32]).unwrap();
        let private = ring.generate_private("Private").unwrap();
        let app = caller("balances_app");
        ring.set_provider_grant(
            app.clone(),
            Grant {
                accounts: [native, fungible, nft, private]
                    .iter()
                    .map(|id| *id.value())
                    .collect(),
                scopes: BTreeSet::from([Scope::PublicBalance, Scope::NftEnumeration]),
            },
        )
        .unwrap();
        let mut provider = Provider::unlocked(ring).unwrap();
        let definition = lee::AccountId::new([8; 32]);
        let token = token_core::TokenHolding::Fungible {
            definition_id: definition,
            balance: u128::MAX,
        };
        let copy = token_core::TokenHolding::NftPrintedCopy {
            definition_id: definition,
            owned: true,
        };
        let wallet = NativeWallet {
            endpoint: "http://configured-node.invalid".into(),
            node: ReadNode {
                accounts: BTreeMap::from([
                    (
                        native,
                        lee::Account {
                            balance: u128::MAX,
                            ..Default::default()
                        },
                    ),
                    (
                        fungible,
                        lee::Account {
                            program_owner: programs::token().id(),
                            data: (&token).into(),
                            ..Default::default()
                        },
                    ),
                    (
                        nft,
                        lee::Account {
                            program_owner: programs::token().id(),
                            data: (&copy).into(),
                            ..Default::default()
                        },
                    ),
                ]),
                calls: Cell::new(0),
            },
        };
        assert!(provider.accounts(&app).is_err());
        let peer = caller("other_app");
        assert!(provider.native_balance(&peer, &wallet, native).is_err());
        assert!(provider.fungible_balance(&peer, &wallet, fungible).is_err());
        assert!(provider.nft_holding(&peer, &wallet, nft).is_err());
        assert!(matches!(
            provider.native_balance(&app, &wallet, private),
            Err(Error::NotPublic)
        ));
        assert_eq!(wallet.node.calls.get(), 0);
        assert_eq!(
            provider.native_balance(&app, &wallet, native).unwrap()["base_units"],
            u128::MAX.to_string()
        );
        assert_eq!(
            provider.fungible_balance(&app, &wallet, fungible).unwrap()["token_base_units"],
            u128::MAX.to_string()
        );
        assert_eq!(
            provider.nft_holding(&app, &wallet, nft).unwrap()["state"]["NftPrintedCopy"]["owned"],
            true
        );
        assert_eq!(wallet.node.calls.get(), 3);
        let injected = serde_json::json!({"method":"native_balance","account":native,"endpoint":"http://attacker.invalid"}).to_string();
        assert!(matches!(
            provider.dispatch(&app, &injected, 100),
            Err(Error::InvalidRequest)
        ));
        provider.revoke_scope(&app, Scope::PublicBalance).unwrap();
        assert!(provider.native_balance(&app, &wallet, native).is_err());
        assert_eq!(wallet.node.calls.get(), 3);
        assert!(provider.nft_holding(&app, &wallet, nft).is_ok());
        assert_eq!(wallet.node.calls.get(), 4);
    }
    #[test]
    fn wire_contract_rejects_identity_and_privileged_operations() {
        assert!(serde_json::from_str::<DappRequest>(r#"{"method":"accounts"}"#).is_ok());
        for request in [
            r#"{"method":"accounts","app_id":"victim"}"#,
            r#"{"method":"accounts","principal":{"kind":"module","name":"victim"}}"#,
            r#"{"method":"request_access","scopes":["Accounts"],"approved":true}"#,
            r#"{"method":"access_status","id":"x","principal":"victim"}"#,
            r#"{"method":"decide_access","approved":true}"#,
            r#"{"method":"set_grant","scopes":["Accounts"]}"#,
            r#"{"method":"grants"}"#,
            r#"{"method":"signing_key"}"#,
        ] {
            assert!(
                serde_json::from_str::<DappRequest>(request).is_err(),
                "accepted {request}"
            );
        }
    }
    #[test]
    fn access_requires_owned_selection_and_survives_restart_and_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.sqlite");
        let mut ring = Keyring::create(&path, PASSWORD).unwrap();
        let account = *ring
            .import_public("Private label", &[1; 32])
            .unwrap()
            .value();
        let other = *ring.import_public("Not shared", &[2; 32]).unwrap().value();
        let mut provider = Provider::unlocked(ring).unwrap();
        let app = caller("app_a");
        let peer = caller("app_b");
        let id = provider
            .request_access(
                &app,
                BTreeSet::from([Scope::Accounts, Scope::PublicBalance]),
                100,
            )
            .unwrap();
        assert!(provider.accounts(&app).is_err());
        assert!(provider.access_status(&peer, &id, 100).is_err());
        assert!(
            provider
                .decide_access(&id, Some(grant(Some(account), &[Scope::Transactions])), 101)
                .is_err()
        );
        assert!(
            provider
                .decide_access(&id, Some(grant(Some([9; 32]), &[Scope::Accounts])), 101)
                .is_err()
        );
        assert_eq!(
            provider.access_status(&app, &id, 101).unwrap(),
            AccessState::Pending
        );
        provider
            .decide_access(
                &id,
                Some(grant(
                    Some(account),
                    &[Scope::Accounts, Scope::PublicBalance],
                )),
                102,
            )
            .unwrap();
        assert_eq!(provider.accounts(&app).unwrap().len(), 1);
        assert_eq!(
            *provider.accounts(&app).unwrap()[0].account.value(),
            account
        );
        assert!(
            !provider
                .permitted(&app, Scope::PublicBalance, Some(other))
                .unwrap()
        );
        assert!(provider.accounts(&peer).is_err());
        assert!(
            provider
                .dispatch(&peer, r#"{"method":"accounts"}"#, 102)
                .is_err()
        );
        for request in [
            r#"{"method":"accounts","app_id":"app_a"}"#,
            r#"{"method":"accounts","principal":{"kind":"module","name":"app_a"}}"#,
            r#"{"method":"decide_access","approved":true}"#,
            r#"{"method":"set_grant","scopes":["Accounts"]}"#,
            r#"{"method":"grants"}"#,
            r#"{"method":"signing_key"}"#,
        ] {
            assert!(matches!(
                provider.dispatch(&app, request, 102),
                Err(Error::InvalidRequest)
            ));
        }
        assert_eq!(
            provider
                .dispatch(&app, r#"{"method":"accounts"}"#, 102)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );

        assert!(provider.decide_access(&id, None, 103).is_err());
        drop(provider);
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(5).any(|w| w == b"app_a"));
        let mut restored = Provider::unlocked(Keyring::open(&path, PASSWORD).unwrap()).unwrap();
        assert!(restored.access_status(&app, &id, 104).is_err());
        assert_eq!(restored.accounts(&app).unwrap().len(), 1);
        let stale_reader = Provider::unlocked(Keyring::open(&path, PASSWORD).unwrap()).unwrap();
        assert_eq!(stale_reader.accounts(&app).unwrap().len(), 1);
        restored.revoke_scope(&app, Scope::PublicBalance).unwrap();
        assert!(stale_reader.accounts(&app).is_err());
        assert!(
            stale_reader
                .permitted(&app, Scope::PublicBalance, Some(account))
                .is_err()
        );
        assert_eq!(restored.accounts(&app).unwrap().len(), 1);
        assert!(
            !restored
                .permitted(&app, Scope::PublicBalance, Some(account))
                .unwrap()
        );
        restored.revoke(&app).unwrap();
        drop(restored);
        let restored = Provider::unlocked(Keyring::open(&path, PASSWORD).unwrap()).unwrap();
        assert!(restored.accounts(&app).is_err());
    }
    #[test]
    fn proof_permission_is_separate_and_failed_commit_grants_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.sqlite");
        let mut ring = Keyring::create(&path, PASSWORD).unwrap();
        let account = *ring.import_public("Account", &[1; 32]).unwrap().value();
        let stale_ring = Keyring::open(&path, PASSWORD).unwrap();
        let mut provider = Provider::unlocked(ring).unwrap();
        let app = caller("proof_app");
        assert!(
            provider
                .request_access(
                    &app,
                    BTreeSet::from([Scope::CollectionProof, Scope::Accounts]),
                    10
                )
                .is_err()
        );
        let id = provider
            .request_access(&app, BTreeSet::from([Scope::CollectionProof]), 10)
            .unwrap();
        assert!(
            provider
                .decide_access(
                    &id,
                    Some(grant(Some(account), &[Scope::CollectionProof])),
                    11
                )
                .is_err()
        );
        provider
            .decide_access(&id, Some(grant(None, &[Scope::CollectionProof])), 12)
            .unwrap();
        assert!(provider.accounts(&app).is_err());
        assert!(
            provider
                .permitted(&app, Scope::CollectionProof, None)
                .unwrap()
        );
        assert!(
            !provider
                .permitted(&app, Scope::Transactions, Some(account))
                .unwrap()
        );
        let access = provider
            .request_access(&app, BTreeSet::from([Scope::Accounts]), 20)
            .unwrap();
        provider
            .decide_access(&access, Some(grant(Some(account), &[Scope::Accounts])), 21)
            .unwrap();
        assert!(
            provider
                .permitted(&app, Scope::CollectionProof, None)
                .unwrap()
        );
        assert_eq!(provider.accounts(&app).unwrap().len(), 1);
        provider.revoke_scope(&app, Scope::Accounts).unwrap();
        assert!(provider.accounts(&app).is_err());
        assert!(
            provider
                .permitted(&app, Scope::CollectionProof, None)
                .unwrap()
        );
        let mut stale = Provider::unlocked(stale_ring).unwrap();
        let id = stale
            .request_access(&app, BTreeSet::from([Scope::Accounts]), 30)
            .unwrap();
        assert!(
            stale
                .decide_access(&id, Some(grant(Some(account), &[Scope::Accounts])), 31)
                .is_err()
        );
        assert!(stale.accounts(&app).is_err());
        assert_eq!(
            stale.access_status(&app, &id, 31).unwrap(),
            AccessState::Pending
        );
        assert!(stale.decide_access(&id, None, 330).is_err());
        let cancelled = provider
            .request_access(&app, BTreeSet::from([Scope::Accounts]), 40)
            .unwrap();
        provider.decide_access(&cancelled, None, 41).unwrap();
        assert_eq!(
            provider.access_status(&app, &cancelled, 41).unwrap(),
            AccessState::Rejected
        );
        assert!(provider.accounts(&app).is_err());
    }
}
