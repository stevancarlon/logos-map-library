// SPDX-License-Identifier: MIT OR Apache-2.0
//! Trusted host dispatcher for v0.3 accounts. The native adapter must supply
//! authenticated caller identity separately from untrusted JSON arguments.
use crate::access::{Requests, State as AccessState};
use crate::{
    AccountId, Error, Node, Result,
    outbox::{Outbox, SubmissionNode},
    transactions::{Proposal, Requests as TransactionRequests},
};
use logos_wallet_policy::{Grant, Scope, principal::Principal};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::{
    collections::BTreeSet,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

pub const OWNER_MODULE: &str = "prize_wallet_ui";
#[derive(Clone, Copy)]
pub enum Channel {
    Owner,
    Dapp,
}
fn secret<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
#[derive(Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
enum OwnerRequest {
    State {},
    ProposeTransaction {
        proposal: Proposal,
    },
    RefreshTransaction {
        id: String,
    },
    RefreshPrivateTransaction {
        id: String,
    },
    AccountState {
        account: AccountId,
    },
    ImportPublic {
        label: String,
        #[serde(deserialize_with = "secret")]
        private_key: Zeroizing<String>,
    },
    GeneratePrivate {
        label: String,
    },
    ImportPrivate {
        label: String,
        #[serde(deserialize_with = "secret")]
        spending_seed: Zeroizing<String>,
        #[serde(deserialize_with = "secret")]
        identifier: Zeroizing<String>,
    },
    ConfigureNetwork {
        endpoint: String,
    },
    DecideTransaction {
        id: String,
        approve: bool,
    },
    Create {
        #[serde(deserialize_with = "secret")]
        password: Zeroizing<String>,
    },
    Unlock {
        #[serde(deserialize_with = "secret")]
        password: Zeroizing<String>,
    },
    Lock {},
    GenerateAccount {
        label: String,
    },
    SelectAccount {
        account: AccountId,
    },
    RenameAccount {
        account: AccountId,
        label: String,
    },
    ChangePassword {
        #[serde(deserialize_with = "secret")]
        current_password: Zeroizing<String>,
        #[serde(deserialize_with = "secret")]
        new_password: Zeroizing<String>,
    },
    DecideAccess {
        id: String,
        accounts: BTreeSet<AccountId>,
        scopes: BTreeSet<Scope>,
        approve: bool,
    },
    SetGrant {
        principal: Principal,
        grant: Option<Grant>,
    },
}
#[derive(Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
enum DappRequest {
    NativeBalance {
        account: AccountId,
    },
    FungibleBalance {
        account: AccountId,
    },
    NftHoldings {
        account: AccountId,
    },
    CollectionMembership {
        account: AccountId,
        collection: AccountId,
    },
    RequestTransaction {
        proposal: Proposal,
    },
    TransactionStatus {
        id: String,
    },
    ReconcileTransaction {
        id: String,
    },
    RequestAccess {
        scopes: BTreeSet<Scope>,
    },
    AccessStatus {
        id: String,
    },
    Accounts {},
    Activity {},
    Status {
        id: String,
    },
}
/// An independently versioned path is required. Never point this session at a
/// legacy wallet. Only the authenticated owner channel can approve signing.
pub struct Session {
    path: PathBuf,
    unlocked: Option<Outbox>,
    access: Requests,
    transactions: TransactionRequests,
    network: Option<String>,
}
impl Session {
    pub fn new(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err(Error::Invalid("wallet path must be absolute"));
        }
        Ok(Self {
            path: path.into(),
            unlocked: None,
            access: Requests::default(),
            transactions: TransactionRequests::default(),
            network: None,
        })
    }
    fn store(&mut self) -> Result<&mut Outbox> {
        self.unlocked
            .as_mut()
            .ok_or(Error::Invalid("wallet is locked"))
    }
    fn node(&self) -> Result<Node> {
        Node::new(
            self.network
                .as_deref()
                .ok_or(Error::Invalid("owner must configure a network first"))?,
        )
    }
    fn state(&mut self, now: u64) -> Result<Value> {
        let snapshot = match &self.unlocked {
            Some(store) => store.owner_snapshot()?,
            None => json!({"accounts":null,"grants":[],"activity":[]}),
        };
        let (private_accounts, private_activity) = match &self.unlocked {
            Some(store) => (
                json!(store.owner_private_accounts()?),
                json!(store.owner_private_activity()?),
            ),
            None => (Value::Null, json!([])),
        };
        Ok(
            json!({"grants":snapshot["grants"],"activity":snapshot["activity"],"private_accounts":private_accounts,"private_activity":private_activity,"protocol":"v0.3", "exists":self.path.exists(), "unlocked":self.unlocked.is_some(), "accounts":snapshot["accounts"],"access_requests":self.access.prompts(now),"network":self.network,"transaction_requests":self.transactions.reviews(now)}),
        )
    }
    /// `caller` comes from the trusted adapter, never a body field. Raw body
    /// ownership/zeroization remains the adapter's responsibility.
    pub fn dispatch(&mut self, caller: &Principal, channel: Channel, body: &str) -> Result<Value> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Invalid("invalid clock"))?
            .as_secs();
        self.dispatch_at(caller, channel, body, now)
    }
    fn dispatch_at(
        &mut self,
        caller: &Principal,
        channel: Channel,
        body: &str,
        now: u64,
    ) -> Result<Value> {
        caller.validate()?;
        if matches!(caller, Principal::LocalCli) {
            return Err(Error::Invalid("authenticated Basecamp caller required"));
        }
        match channel {
            Channel::Owner => {
                if !matches!(caller, Principal::Module { name, instance } if name == OWNER_MODULE && instance.is_empty())
                {
                    return Err(Error::Invalid("wallet owner channel denied"));
                }
                if body.len() > 16384 {
                    return Err(Error::Invalid("owner request too large"));
                }
                // Never return serde's unknown-variant diagnostic: it can quote
                // attacker-supplied secret text from the method field.
                let request: OwnerRequest = serde_json::from_str(body)
                    .map_err(|_| Error::Invalid("invalid owner request"))?;
                match request {
                    OwnerRequest::State {} => return self.state(now),
                    OwnerRequest::ProposeTransaction { proposal } => {
                        let node = self.node()?;
                        let store = self
                            .unlocked
                            .as_mut()
                            .ok_or(Error::Invalid("wallet is locked"))?;
                        store.owner_allow_account(caller, proposal.from)?;
                        self.transactions.invalidate_principal(caller);
                        return Ok(
                            json!({"id":self.transactions.propose(store,caller,&node,proposal,now)?,"state":"pending_approval"}),
                        );
                    }
                    OwnerRequest::RefreshTransaction { id } => {
                        let node = self.node()?;
                        let result = self.store()?.owner_reconcile(&id, &node, now);
                        self.transactions.invalidate();
                        return Ok(json!({"transaction":result?,"execution_outcome":"unknown"}));
                    }
                    OwnerRequest::RefreshPrivateTransaction { id } => {
                        let node = self.node()?;
                        let result = self.store()?.owner_reconcile_private(&id, &node, now);
                        self.transactions.invalidate();
                        return result;
                    }
                    OwnerRequest::AccountState { account } => {
                        if !self
                            .store()?
                            .owner_accounts()?
                            .iter()
                            .any(|a| a.account == account)
                        {
                            return Err(Error::Invalid("owned account required"));
                        }
                        return Ok(
                            json!({"account_state":crate::inventory::read(&self.node()?,account)?}),
                        );
                    }
                    OwnerRequest::ImportPublic { label, private_key } => {
                        let mut key = Zeroizing::new([0u8; 32]);
                        if private_key.len() != 64
                            || hex::decode_to_slice(private_key.as_bytes(), &mut *key).is_err()
                        {
                            return Err(Error::Invalid(
                                "expected 64 hexadecimal private-key characters",
                            ));
                        }
                        let account = self.store()?.owner_import_public(key, &label)?;
                        self.transactions.invalidate();
                        return Ok(json!({"account":account,"privacy":"public","protocol":"v0.3"}));
                    }
                    OwnerRequest::GeneratePrivate { label } => {
                        let account = self.store()?.owner_create_private(&label)?;
                        self.transactions.invalidate();
                        return Ok(
                            json!({"account":account,"privacy":"private","protocol":"v0.3"}),
                        );
                    }
                    OwnerRequest::ImportPrivate {
                        label,
                        spending_seed,
                        identifier,
                    } => {
                        let mut seed = Zeroizing::new([0; 32]);
                        let mut identifier_bytes = Zeroizing::new([0; 32]);
                        if spending_seed.len() != 64
                            || identifier.len() != 64
                            || hex::decode_to_slice(spending_seed.as_bytes(), &mut *seed).is_err()
                            || hex::decode_to_slice(identifier.as_bytes(), &mut *identifier_bytes)
                                .is_err()
                        {
                            return Err(Error::Invalid(
                                "expected 64 hexadecimal characters each for seed and identifier",
                            ));
                        }
                        let account = self.store()?.owner_import_private(
                            crate::shielded::PrivateIdentity::from_seed(seed, *identifier_bytes),
                            &label,
                        )?;
                        self.transactions.invalidate();
                        return Ok(
                            json!({"account":account,"privacy":"private","protocol":"v0.3","history_recovered":false}),
                        );
                    }
                    OwnerRequest::ConfigureNetwork { endpoint } => {
                        let node = Node::new(&endpoint)?;
                        self.store()?.owner_cancel_pending()?;
                        self.transactions.invalidate();
                        self.network = Some(node.endpoint().into());
                    }
                    OwnerRequest::DecideTransaction { id, approve } => {
                        let node = self.node()?;
                        let store = self
                            .unlocked
                            .as_mut()
                            .ok_or(Error::Invalid("wallet is locked"))?;
                        return self.transactions.decide(store, &node, &id, approve, now);
                    }
                    OwnerRequest::Create { password } => {
                        if self.unlocked.is_some() {
                            return Err(Error::Invalid("wallet is already unlocked"));
                        }
                        if password.is_empty() || password.len() > 4096 {
                            return Err(Error::Invalid("invalid password length"));
                        }
                        let mut directory = std::fs::DirBuilder::new();
                        directory.recursive(true);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::DirBuilderExt;
                            directory.mode(0o700);
                        }
                        directory
                            .create(
                                self.path
                                    .parent()
                                    .ok_or(Error::Invalid("invalid wallet path"))?,
                            )
                            .map_err(|_| Error::Invalid("cannot create wallet directory"))?;
                        self.unlocked = Some(Outbox::create(&self.path, password.as_bytes())?);
                        self.access.clear();
                    }
                    OwnerRequest::Unlock { password } => {
                        // Failed replacement authentication must not leave an
                        // earlier unlocked session usable.
                        self.access.clear();
                        self.transactions.clear();
                        self.network = None;
                        self.unlocked = None;
                        self.unlocked = Some(Outbox::open(&self.path, password.as_bytes())?);
                    }
                    OwnerRequest::Lock {} => {
                        self.access.clear();
                        self.transactions.clear();
                        self.network = None;
                        self.unlocked = None;
                    }
                    OwnerRequest::GenerateAccount { label } => {
                        let account = self.store()?.owner_create_public(&label)?;
                        self.transactions.invalidate();
                        return Ok(json!({"account":account,"privacy":"public","protocol":"v0.3"}));
                    }
                    OwnerRequest::SelectAccount { account } => {
                        self.store()?.owner_select(account)?;
                        self.transactions.invalidate();
                    }
                    OwnerRequest::RenameAccount { account, label } => {
                        self.store()?.owner_rename(account, &label)?;
                        self.transactions.invalidate();
                    }
                    OwnerRequest::ChangePassword {
                        current_password,
                        new_password,
                    } => {
                        self.store()?.owner_rotate_password(
                            current_password.as_bytes(),
                            new_password.as_bytes(),
                        )?;
                        self.access.clear();
                        self.transactions.invalidate();
                    }
                    OwnerRequest::DecideAccess {
                        id,
                        accounts,
                        scopes,
                        approve,
                    } => {
                        let grant = approve.then(|| Grant {
                            accounts: accounts.into_iter().map(AccountId::bytes).collect(),
                            scopes,
                        });
                        let principal = self.access.selection(&id, grant.as_ref(), now)?;
                        if let Some(grant) = &grant {
                            self.store()?
                                .owner_set_grant(&principal, Some(grant.clone()))?;
                            self.transactions.invalidate();
                        } else {
                            // A rejection also requires a current unlocked store.
                            self.store()?.grant_for(&principal)?;
                        }
                        self.access.complete(&id, grant);
                    }
                    OwnerRequest::SetGrant { principal, grant } => {
                        if matches!(principal, Principal::LocalCli) {
                            return Err(Error::Invalid("terminal grants are not Basecamp grants"));
                        }
                        self.store()?.owner_set_grant(&principal, grant)?;
                        self.access.remove_principal(&principal);
                        self.transactions.invalidate();
                    }
                }
                self.state(now)
            }
            Channel::Dapp => {
                if body.len() > 8192 {
                    return Err(Error::Invalid("app request too large"));
                }
                let request: DappRequest = serde_json::from_str(body)
                    .map_err(|_| Error::Invalid("invalid app request"))?;
                Ok(match request {
                    DappRequest::RequestTransaction { proposal } => {
                        let node = self.node()?;
                        let store = self
                            .unlocked
                            .as_mut()
                            .ok_or(Error::Invalid("wallet is locked"))?;
                        json!({"id":self.transactions.propose(store,caller,&node,proposal,now)?,"state":"pending_approval"})
                    }
                    DappRequest::TransactionStatus { id } => {
                        let store = self
                            .unlocked
                            .as_ref()
                            .ok_or(Error::Invalid("wallet is locked"))?;
                        self.transactions.status(store, caller, &id, now)?
                    }
                    DappRequest::ReconcileTransaction { id } => {
                        let node = self.node()?;
                        let result = self.store()?.reconcile(caller, &id, &node, now);
                        self.transactions.invalidate();
                        json!({"transaction":result?,"execution_outcome":"unknown"})
                    }
                    DappRequest::RequestAccess { scopes } => {
                        self.store()?.grant_for(caller)?;
                        json!({"id":self.access.request(caller, scopes, now)?,"state":"pending"})
                    }
                    DappRequest::AccessStatus { id } => {
                        let current = self.store()?.grant_for(caller)?;
                        let status = self.access.status(caller, &id, now)?;
                        if let AccessState::Approved { grant } = &status
                            && current.as_ref() != Some(grant)
                        {
                            return Err(Error::Invalid("access grant changed"));
                        }
                        match status {
                            AccessState::Approved { grant } => {
                                json!({"state":"approved","accounts":grant.accounts.into_iter().map(AccountId::from_bytes).collect::<Vec<_>>(),"scopes":grant.scopes})
                            }
                            other => json!(other),
                        }
                    }
                    DappRequest::NativeBalance { account } => {
                        let node = self.node()?;
                        self.store()?.native_balance_for(caller, &node, account)?
                    }
                    DappRequest::FungibleBalance { account } => {
                        let node = self.node()?;
                        self.store()?.fungible_balance_for(caller, &node, account)?
                    }
                    DappRequest::NftHoldings { account } => {
                        let node = self.node()?;
                        self.store()?.nft_holdings_for(caller, &node, account)?
                    }
                    DappRequest::CollectionMembership {
                        account,
                        collection,
                    } => {
                        let node = self.node()?;
                        self.store()?
                            .collection_membership_for(caller, &node, account, collection)?
                    }
                    DappRequest::Accounts {} => {
                        json!({"protocol":"v0.3","accounts":self.store()?.accounts_for(caller)?})
                    }
                    DappRequest::Activity {} => {
                        json!({"transactions":self.store()?.activity_for(caller)?,"execution_outcome":"unknown"})
                    }
                    DappRequest::Status { id } => {
                        json!({"transaction":self.store()?.status(caller,&id)?,"execution_outcome":"unknown"})
                    }
                })
            }
        }
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
