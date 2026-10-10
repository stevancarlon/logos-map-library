// SPDX-License-Identifier: MIT OR Apache-2.0
//! Native module session. The adapter supplies ambient caller identity, never
//! identity from the request body. Only the installed wallet UI controls keys,
//! connection grants and individual transaction decisions.
use super::*;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const OWNER_MODULE: &str = "prize_wallet_ui";
#[derive(Clone, Copy)]
pub enum Channel {
    Dapp,
    Owner,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceSelection {
    program: String,
    registrant: lee::AccountId,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceSettings {
    registry: String,
    receipts: PathBuf,
    registrations: Vec<SourceSelection>,
}
impl SourceSettings {
    fn config(
        &self,
    ) -> std::result::Result<logos_registry_sdk::verification::ReviewConfig, String> {
        let mut authors = BTreeMap::new();
        for selection in &self.registrations {
            let program = logos_registry_sdk::parse_program(&selection.program)
                .map_err(|error| error.to_string())?;
            if authors
                .insert(
                    logos_registry_sdk::program_bytes(&program),
                    *selection.registrant.value(),
                )
                .is_some()
            {
                return Err("Choose only one author registration per program".into());
            }
        }
        logos_registry_sdk::verification::ReviewConfig::new(
            &self.registry,
            self.receipts.clone(),
            authors,
        )
        .map_err(|error| error.to_string())
    }
}
#[derive(Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
enum OwnerRequest {
    State {},
    ProposeTransaction {
        proposal: transactions::TransactionProposal,
    },
    RefreshTransaction {
        id: String,
    },
    AccountState {
        account: lee::AccountId,
    },
    Create {
        password: String,
    },
    Unlock {
        password: String,
    },
    Lock {},
    Backup {
        path: PathBuf,
        password: String,
    },
    Restore {
        path: PathBuf,
        password: String,
    },
    ChangePassword {
        current_password: String,
        new_password: String,
    },
    ConfigureSourceReview {
        settings: Option<SourceSettings>,
    },
    ConfigureNetwork {
        endpoint: String,
    },
    GenerateAccount {
        label: String,
        private: bool,
    },
    SelectAccount {
        account: lee::AccountId,
    },
    RenameAccount {
        account: lee::AccountId,
        label: String,
    },
    DecideAccess {
        id: String,
        accounts: Vec<lee::AccountId>,
        scopes: BTreeSet<Scope>,
        approve: bool,
    },
    DecideTransaction {
        id: String,
        approve: bool,
    },
    RevokeAccount {
        principal: Principal,
        account: lee::AccountId,
    },
    RevokeScope {
        principal: Principal,
        scope: Scope,
    },
    Revoke {
        principal: Principal,
    },
}
/// Decrypted session state exists only while unlocked. Lock drops the entire
/// provider, its keyring and pending approvals. Unlock restores durable grants.
pub struct NativeSession {
    path: PathBuf,
    provider: Option<Provider>,
    endpoint: Option<String>,
    source_settings: Option<SourceSettings>,
}
impl NativeSession {
    pub fn new(path: &Path) -> std::result::Result<Self, String> {
        if !path.is_absolute() {
            return Err("Wallet path must be absolute".into());
        }
        Ok(Self {
            path: path.into(),
            provider: None,
            endpoint: None,
            source_settings: None,
        })
    }
    fn provider(&mut self) -> std::result::Result<&mut Provider, String> {
        self.provider
            .as_mut()
            .ok_or_else(|| "Unlock the wallet first".into())
    }
    pub fn dispatch(
        &mut self,
        caller: &Principal,
        channel: Channel,
        body: &str,
        now: u64,
    ) -> std::result::Result<serde_json::Value, String> {
        caller.validate().map_err(|error| error.to_string())?;
        match channel {
            Channel::Dapp => self
                .provider()?
                .dispatch(caller, body, now)
                .map_err(|error| error.to_string()),
            Channel::Owner => {
                // Derived identities are not owner authority, even with this
                // parent. Basecamp 0.3.2 currently gives its UI an empty instance.
                if !matches!(caller, Principal::Module { name, instance } if name == OWNER_MODULE && instance.is_empty())
                {
                    return Err("Wallet management is restricted to the installed wallet UI".into());
                }
                if body.len() > 16384 {
                    return Err("Wallet request exceeds size limit".into());
                }
                let request: OwnerRequest =
                    serde_json::from_str(body).map_err(|_| "Invalid wallet management request")?;
                self.owner(request, now)
            }
        }
    }
    fn snapshot(&mut self, now: u64) -> std::result::Result<serde_json::Value, String> {
        let Some(provider) = &mut self.provider else {
            return Ok(serde_json::json!({"unlocked":false,"exists":self.path.exists()}));
        };
        provider
            .keyring
            .ensure_current()
            .map_err(|error| error.to_string())?;
        let accounts = provider
            .keyring
            .accounts()
            .map_err(|error| error.to_string())?;
        let access = provider.access_prompts(now);
        let transactions = provider.transaction_prompts(now);
        Ok(
            serde_json::json!({"unlocked":true,"exists":true,"network":self.endpoint,"source_review":self.source_settings,"accounts":accounts,"grants":provider.grants(),"access_requests":access,"transaction_requests":transactions,"outbox":provider.keyring.public_outbox()}),
        )
    }
    fn owner(
        &mut self,
        request: OwnerRequest,
        now: u64,
    ) -> std::result::Result<serde_json::Value, String> {
        match request {
            OwnerRequest::State {} => return self.snapshot(now),
            OwnerRequest::ProposeTransaction { proposal } => {
                let provider = self.provider()?;
                let wallet = provider.network.take().ok_or("Select a sequencer first")?;
                let result = provider.propose_owner_transaction(&wallet, proposal, now);
                provider.network = Some(wallet);
                return Ok(
                    serde_json::json!({"proposal_id":result.map_err(|error| error.to_string())?}),
                );
            }
            OwnerRequest::RefreshTransaction { id } => {
                let provider = self.provider()?;
                let endpoint = &provider
                    .network
                    .as_ref()
                    .ok_or("Select the original sequencer first")?
                    .endpoint;
                provider
                    .keyring
                    .reconcile_owner_public_submission(&id, endpoint, now)
                    .map_err(|error| error.to_string())?;
            }
            OwnerRequest::AccountState { account } => {
                let provider = self.provider()?;
                let wallet = provider
                    .network
                    .as_ref()
                    .ok_or("Select a sequencer first")?;
                let state = provider
                    .owner_account_state(wallet, account, now)
                    .map_err(|error| error.to_string())?;
                return Ok(serde_json::json!({"account_state":state}));
            }
            OwnerRequest::Create { password } => {
                self.unlock(password, true)?;
            }
            OwnerRequest::Unlock { password } => {
                self.unlock(password, false)?;
            }
            OwnerRequest::Backup { path, password } => {
                let password = Zeroizing::new(password);
                self.provider()?
                    .keyring
                    .backup(&path, password.as_bytes())
                    .map_err(|error| error.to_string())?;
                return Ok(serde_json::json!({"backup_saved":true}));
            }
            OwnerRequest::Restore { path, password } => {
                let password = Zeroizing::new(password);
                if self.provider.is_some() || self.path.exists() {
                    return Err("Restore requires a new wallet profile; existing wallets are never replaced".into());
                }
                let parent = self.path.parent().ok_or("Wallet directory missing")?;
                std::fs::create_dir_all(parent).map_err(|_| "Cannot create wallet directory")?;
                drop(
                    Keyring::restore(&path, &self.path, password.as_bytes())
                        .map_err(|error| error.to_string())?,
                );
                self.endpoint = None;
                self.source_settings = None;
                // Explicit unlock is required after restoration.
            }
            OwnerRequest::ChangePassword {
                current_password,
                new_password,
            } => {
                let current = Zeroizing::new(current_password);
                let new = Zeroizing::new(new_password);
                if current.is_empty() || current.len() > 4096 || new.is_empty() || new.len() > 4096
                {
                    return Err("Enter passwords of at most 4096 bytes".into());
                }
                self.provider()?;
                // Authenticate independently; possession of an unlocked window is
                // insufficient to replace the owner's password.
                drop(
                    Keyring::open(&self.path, current.as_bytes())
                        .map_err(|_| "Current password could not unlock the wallet")?,
                );
                self.provider()?
                    .keyring
                    .rotate_password(new.as_bytes())
                    .map_err(|error| error.to_string())?;
                // No pending approvals or network selection survive this action.
                self.provider = None;
                self.endpoint = None;
                self.source_settings = None;
            }
            OwnerRequest::Lock {} => {
                self.provider = None;
                self.endpoint = None;
                self.source_settings = None;
            }
            OwnerRequest::ConfigureSourceReview { settings } => {
                let config = settings.as_ref().map(SourceSettings::config).transpose()?;
                self.provider()?.configure_source_review(config);
                self.source_settings = settings;
            }
            OwnerRequest::ConfigureNetwork { endpoint } => {
                self.provider()?
                    .configure_network(&endpoint)
                    .map_err(|error| error.to_string())?;
                self.endpoint = Some(endpoint.trim_end_matches('/').into());
            }
            OwnerRequest::GenerateAccount { label, private } => {
                let provider = self.provider()?;
                if private {
                    provider.keyring.generate_private(&label)
                } else {
                    provider.keyring.generate_public(&label)
                }
                .map_err(|error| error.to_string())?;
            }
            OwnerRequest::SelectAccount { account } => {
                self.provider()?
                    .keyring
                    .select(account)
                    .map_err(|error| error.to_string())?;
            }
            OwnerRequest::RenameAccount { account, label } => {
                self.provider()?
                    .keyring
                    .rename(account, &label)
                    .map_err(|error| error.to_string())?;
            }
            OwnerRequest::DecideAccess {
                id,
                accounts,
                scopes,
                approve,
            } => {
                let grant = approve.then(|| Grant {
                    accounts: accounts.iter().map(|id| *id.value()).collect(),
                    scopes,
                });
                self.provider()?
                    .decide_access(&id, grant, now)
                    .map_err(|error| error.to_string())?;
            }
            OwnerRequest::DecideTransaction { id, approve } => {
                let result = self
                    .provider()?
                    .decide_configured_transaction(&id, approve, now)
                    .map_err(|error| error.to_string())?;
                return Ok(serde_json::json!({"transaction":result}));
            }
            OwnerRequest::RevokeAccount { principal, account } => {
                self.provider()?
                    .revoke_account(&principal, *account.value())
                    .map_err(|error| error.to_string())?;
            }
            OwnerRequest::RevokeScope { principal, scope } => {
                self.provider()?
                    .revoke_scope(&principal, scope)
                    .map_err(|error| error.to_string())?;
            }
            OwnerRequest::Revoke { principal } => {
                self.provider()?
                    .revoke(&principal)
                    .map_err(|error| error.to_string())?;
            }
        }
        self.snapshot(now)
    }
    fn unlock(&mut self, password: String, create: bool) -> std::result::Result<(), String> {
        let password = Zeroizing::new(password);
        if self.provider.is_some() {
            return Err("Lock the current wallet first".into());
        }
        if password.is_empty() || password.len() > 4096 {
            return Err("Enter a wallet password of at most 4096 bytes".into());
        }
        if create {
            let parent = self.path.parent().ok_or("Wallet directory missing")?;
            std::fs::create_dir_all(parent).map_err(|_| "Cannot create wallet directory")?;
        }
        let keyring = if create {
            Keyring::create(&self.path, password.as_bytes())
        } else {
            Keyring::open(&self.path, password.as_bytes())
        }
        .map_err(|error| error.to_string())?;
        self.provider = Some(Provider::unlocked(keyring).map_err(|error| error.to_string())?);
        self.endpoint = None;
        self.source_settings = None;
        Ok(())
    }
}

impl Provider {
    /// Trusted owner channel only. Public state is queried only for owned public
    /// accounts. Private addresses are never sent to getAccount by this method.
    pub fn owner_account_state<N: Node>(
        &self,
        wallet: &NativeWallet<N>,
        account: lee::AccountId,
        now: u64,
    ) -> Result<serde_json::Value> {
        self.keyring.ensure_current()?;
        let info = self
            .keyring
            .accounts()?
            .into_iter()
            .find(|info| info.account == account)
            .ok_or(crate::keyring::Error::NotFound)?;
        let (state, source, vault) = if info.privacy == "private" {
            match self
                .keyring
                .last_included_private_state(&wallet.endpoint, account)
            {
                Ok(state) => (state, "local_private_cache", None),
                Err(crate::keyring::Error::NotFound) => {
                    return Ok(
                        serde_json::json!({"account":account,"privacy":"private","kind":"not_synchronized","network":wallet.endpoint,"source":"local_private_cache","native_base_units":null,"observed_at":now}),
                    );
                }
                Err(crate::keyring::Error::PrivatePending) => {
                    return Ok(
                        serde_json::json!({"account":account,"privacy":"private","kind":"private_operation_pending","network":wallet.endpoint,"source":"local_private_cache","native_base_units":null,"observed_at":now}),
                    );
                }
                Err(error) => return Err(error.into()),
            }
        } else {
            let state = wallet.node.account(account).map_err(crate::Error::from)?;
            let vault_id = vault_core::compute_vault_account_id(programs::vault().id(), account);
            let vault = wallet.node.account(vault_id).map_err(crate::Error::from)?;
            if vault != lee::Account::default()
                && vault.program_owner != programs::authenticated_transfer().id()
            {
                return Err(crate::Error::Invalid(
                    "Unexpected owner for the account's native vault",
                )
                .into());
            }
            (
                state,
                "configured_sequencer",
                Some(vault.balance.to_string()),
            )
        };
        let (kind, holding) = if state.program_owner == programs::authenticated_transfer().id() {
            ("native", None)
        } else if state.program_owner == programs::token().id() {
            let value = token_core::TokenHolding::try_from(&state.data)
                .map_err(|_| crate::Error::Invalid("Invalid token holding data"))?;
            ("token", Some(crate::token::HoldingView::from(value)))
        } else if state == lee::Account::default() {
            ("uninitialized", None)
        } else {
            ("unsupported_program", None)
        };
        Ok(
            serde_json::json!({"account":account,"privacy":info.privacy,"kind":kind,"network":wallet.endpoint,"source":source,"native_base_units":state.balance.to_string(),"vault_base_units":vault,"holding":holding,"metadata_status":"not_fetched","observed_at":now}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owner() -> Principal {
        Principal::Module {
            name: OWNER_MODULE.into(),
            instance: String::new(),
        }
    }
    #[test]
    fn native_source_settings_are_owner_only_validated_and_cleared_on_lock() {
        let dir = tempfile::tempdir().unwrap();
        let mut session = NativeSession::new(&dir.path().join("wallet.sqlite")).unwrap();
        session
            .dispatch(
                &owner(),
                Channel::Owner,
                r#"{"method":"create","password":"source settings fixture"}"#,
                1,
            )
            .unwrap();
        let settings = serde_json::json!({"registry":"11".repeat(32),"receipts":dir.path().join("receipts"),"registrations":[{"program":"22".repeat(32),"registrant":lee::AccountId::new([3;32])}]});
        let request =
            serde_json::json!({"method":"configure_source_review","settings":settings}).to_string();
        let app = Principal::Module {
            name: "other_app".into(),
            instance: String::new(),
        };
        assert!(session.dispatch(&app, Channel::Owner, &request, 2).is_err());
        assert!(session.dispatch(&app, Channel::Dapp, &request, 2).is_err());
        let value = session
            .dispatch(&owner(), Channel::Owner, &request, 3)
            .unwrap();
        assert_eq!(value["source_review"], settings);
        let mut bad = settings.clone();
        bad["receipts"] = serde_json::json!("relative/path");
        assert!(
            session
                .dispatch(
                    &owner(),
                    Channel::Owner,
                    &serde_json::json!({"method":"configure_source_review","settings":bad})
                        .to_string(),
                    4
                )
                .is_err()
        );
        bad = settings.clone();
        bad["registrations"]
            .as_array_mut()
            .unwrap()
            .push(settings["registrations"][0].clone());
        assert!(
            session
                .dispatch(
                    &owner(),
                    Channel::Owner,
                    &serde_json::json!({"method":"configure_source_review","settings":bad})
                        .to_string(),
                    4
                )
                .is_err()
        );
        assert_eq!(session.snapshot(5).unwrap()["source_review"], settings);
        session
            .dispatch(&owner(), Channel::Owner, r#"{"method":"lock"}"#, 6)
            .unwrap();
        let value = session
            .dispatch(
                &owner(),
                Channel::Owner,
                r#"{"method":"unlock","password":"source settings fixture"}"#,
                7,
            )
            .unwrap();
        assert!(value["source_review"].is_null());
    }

    #[test]
    fn native_password_change_authenticates_preserves_accounts_and_locks() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wallet.sqlite");
        let mut session = NativeSession::new(&path).unwrap();
        session
            .dispatch(
                &owner(),
                Channel::Owner,
                r#"{"method":"create","password":"original secret"}"#,
                1,
            )
            .unwrap();
        session
            .dispatch(
                &owner(),
                Channel::Owner,
                r#"{"method":"generate_account","label":"public","private":false}"#,
                2,
            )
            .unwrap();
        let before = session
            .dispatch(
                &owner(),
                Channel::Owner,
                r#"{"method":"generate_account","label":"private","private":true}"#,
                3,
            )
            .unwrap();
        let change = r#"{"method":"change_password","current_password":"original secret","new_password":"replacement secret"}"#;
        let app = Principal::Module {
            name: "untrusted_app".into(),
            instance: String::new(),
        };
        assert!(session.dispatch(&app, Channel::Owner, change, 4).is_err());
        assert!(session.dispatch(&app, Channel::Dapp, change, 4).is_err());
        assert!(
            session
                .dispatch(
                    &owner(),
                    Channel::Owner,
                    &change.replace("original secret", "wrong secret"),
                    4
                )
                .is_err()
        );
        assert_eq!(session.snapshot(4).unwrap()["accounts"], before["accounts"]);
        let result = session
            .dispatch(&owner(), Channel::Owner, change, 5)
            .unwrap();
        assert_eq!(result["unlocked"], false);
        assert!(Keyring::open(&path, b"original secret").is_err());
        let result = session
            .dispatch(
                &owner(),
                Channel::Owner,
                r#"{"method":"unlock","password":"replacement secret"}"#,
                6,
            )
            .unwrap();
        assert_eq!(result["accounts"], before["accounts"]);
        assert_eq!(result["network"], serde_json::Value::Null);
    }

    #[test]
    fn owner_authority_is_ambient_and_lock_drops_pending_approvals() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wallet.sqlite");
        let mut session = NativeSession::new(&path).unwrap();
        let app = Principal::Module {
            name: "untrusted_app".into(),
            instance: String::new(),
        };
        for caller in [
            &app,
            &Principal::Derived {
                parent: OWNER_MODULE.into(),
                leaf: "untrusted_child".into(),
            },
            &Principal::Module {
                name: OWNER_MODULE.into(),
                instance: "unexpected_instance".into(),
            },
        ] {
            assert!(
                session
                    .dispatch(
                        caller,
                        Channel::Owner,
                        r#"{"method":"create","password":"fixture password"}"#,
                        1
                    )
                    .is_err()
            );
        }
        assert!(!path.exists());
        assert!(session.dispatch(&app, Channel::Dapp, r#"{"method":"create","password":"fixture password","principal":{"kind":"module","name":"prize_wallet_ui"}}"#,1).is_err());
        assert!(!path.exists());
        let state = session
            .dispatch(
                &owner(),
                Channel::Owner,
                r#"{"method":"create","password":"fixture password"}"#,
                1,
            )
            .unwrap();
        assert_eq!(state["accounts"], serde_json::json!([]));
        assert!(
            session
                .dispatch(
                    &owner(),
                    Channel::Owner,
                    r#"{"method":"create","password":"replacement"}"#,
                    1
                )
                .is_err()
        );
        let state = session
            .dispatch(
                &owner(),
                Channel::Owner,
                r#"{"method":"generate_account","label":"New account","private":false}"#,
                1,
            )
            .unwrap();
        let account = state["accounts"][0]["account"].clone();
        let request = session
            .dispatch(
                &app,
                Channel::Dapp,
                r#"{"method":"request_access","scopes":["Accounts"]}"#,
                2,
            )
            .unwrap();
        let body = serde_json::json!({"method":"decide_access","id":request["id"],"accounts":[account],"scopes":["Accounts"],"approve":true}).to_string();
        assert!(session.dispatch(&app, Channel::Owner, &body, 3).is_err());
        assert!(session.dispatch(&owner(), Channel::Dapp, &body, 3).is_err());
        assert!(
            session
                .dispatch(&app, Channel::Dapp, r#"{"method":"accounts"}"#, 3)
                .is_err()
        );
        session
            .dispatch(&owner(), Channel::Owner, &body, 3)
            .unwrap();
        assert_eq!(
            session
                .dispatch(&app, Channel::Dapp, r#"{"method":"accounts"}"#, 3)
                .unwrap()[0]["account"],
            account
        );
        let pending = session
            .dispatch(
                &app,
                Channel::Dapp,
                r#"{"method":"request_access","scopes":["Transactions"]}"#,
                4,
            )
            .unwrap();
        session
            .dispatch(&owner(), Channel::Owner, r#"{"method":"lock"}"#, 4)
            .unwrap();
        assert!(
            session
                .dispatch(&app, Channel::Dapp, r#"{"method":"accounts"}"#, 4)
                .is_err()
        );
        assert!(
            session
                .dispatch(
                    &owner(),
                    Channel::Owner,
                    r#"{"method":"unlock","password":"wrong"}"#,
                    4
                )
                .is_err()
        );
        session
            .dispatch(
                &owner(),
                Channel::Owner,
                r#"{"method":"unlock","password":"fixture password"}"#,
                4,
            )
            .unwrap();
        assert_eq!(
            session
                .dispatch(&app, Channel::Dapp, r#"{"method":"accounts"}"#, 4)
                .unwrap()[0]["account"],
            account
        );
        assert!(
            session
                .dispatch(
                    &app,
                    Channel::Dapp,
                    &serde_json::json!({"method":"access_status","id":pending["id"]}).to_string(),
                    4
                )
                .is_err()
        );
        assert!(
            session
                .dispatch(
                    &owner(),
                    Channel::Owner,
                    r#"{"method":"state","approve":true}"#,
                    4
                )
                .is_err()
        );
    }
    #[test]
    fn owner_reads_keep_private_accounts_local_and_preserve_full_balances() {
        use std::{cell::Cell, collections::BTreeMap};
        struct Memory {
            accounts: BTreeMap<lee::AccountId, lee::Account>,
            calls: Cell<usize>,
        }
        impl logos_registry_sdk::AccountReader for Memory {
            fn account(&self, id: lee::AccountId) -> logos_registry_sdk::Result<lee::Account> {
                self.calls.set(self.calls.get() + 1);
                Ok(self.accounts.get(&id).cloned().unwrap_or_default())
            }
        }
        impl Node for Memory {
            fn submit_transaction(
                &self,
                _: &common::transaction::LeeTransaction,
            ) -> logos_registry_sdk::Result<common::HashType> {
                panic!("read must not submit")
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let mut ring =
            Keyring::create(&dir.path().join("wallet.sqlite"), b"owner read fixture").unwrap();
        let public = ring.generate_public("Public").unwrap();
        let private = ring.generate_private("Private").unwrap();
        let mut provider = Provider::unlocked(ring).unwrap();
        let mut wallet = NativeWallet {
            endpoint: "http://fixture.invalid".into(),
            node: Memory {
                accounts: BTreeMap::from([(
                    public,
                    lee::Account {
                        balance: u128::MAX,
                        program_owner: programs::authenticated_transfer().id(),
                        ..Default::default()
                    },
                )]),
                calls: Cell::new(0),
            },
        };
        assert!(
            provider
                .owner_account_state(&wallet, lee::AccountId::new([99; 32]), 1)
                .is_err()
        );
        let state = provider.owner_account_state(&wallet, private, 1).unwrap();
        assert_eq!(state["kind"], "not_synchronized");
        assert!(state["native_base_units"].is_null());
        assert_eq!(wallet.node.calls.get(), 0);
        let state = provider.owner_account_state(&wallet, public, 1).unwrap();
        assert_eq!(state["native_base_units"], u128::MAX.to_string());
        assert_eq!(state["vault_base_units"], "0");
        assert_eq!(state["source"], "configured_sequencer");
        let definition = lee::AccountId::new([44; 32]);
        wallet.node.accounts.insert(
            public,
            lee::Account {
                program_owner: programs::token().id(),
                data: borsh::to_vec(&token_core::TokenHolding::Fungible {
                    definition_id: definition,
                    balance: u128::MAX,
                })
                .unwrap()
                .try_into()
                .unwrap(),
                ..Default::default()
            },
        );
        let state = provider.owner_account_state(&wallet, public, 1).unwrap();
        assert_eq!(
            state["holding"]["Fungible"]["balance"],
            u128::MAX.to_string()
        );
        assert_eq!(
            state["holding"]["Fungible"]["definition_id"],
            serde_json::json!(definition)
        );
        wallet.node.accounts.get_mut(&public).unwrap().data = vec![255].try_into().unwrap();
        assert!(provider.owner_account_state(&wallet, public, 1).is_err());
        assert!(
            provider
                .dispatch(
                    &owner(),
                    &serde_json::json!({"method":"account_state","account":public}).to_string(),
                    1
                )
                .is_err()
        );
    }
}
