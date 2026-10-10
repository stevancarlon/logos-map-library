// SPDX-License-Identifier: MIT OR Apache-2.0
//! Explicit LEZ v0.3 transport and approved native signing. No v0.2 account migration.
//! Wire contract: logos-execution-zone db66590ab821a4e142c211017a3866d007f6fa77.
use base58::{FromBase58, ToBase58};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fmt, str::FromStr, time::Duration};

mod access;
pub mod accounts;
pub mod app_reads;
mod bridge;
pub mod deployment;
pub mod inventory;
pub mod outbox;
pub mod session;
pub mod shielded;
pub mod token;
pub mod transactions;
pub mod transfer;

pub const UPSTREAM_REVISION: &str = "db66590ab821a4e142c211017a3866d007f6fa77";
pub const MAX_SHARD_BYTES: usize = 100 * 1024;
pub const NATIVE_PROGRAM: AccountId = AccountId([0; 32]);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Store(#[from] logos_wallet_store::Error),
    #[error(transparent)]
    Policy(#[from] logos_wallet_policy::Error),
    #[error("Invalid v0.3 response: {0}")]
    Invalid(&'static str),
    #[error("Transport: {0}")]
    Transport(String),
    #[error("RPC response could not be decoded: {0}")]
    Decode(#[from] serde_json::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AccountId([u8; 32]);
impl AccountId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}
impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_base58())
    }
}
impl From<AccountId> for String {
    fn from(value: AccountId) -> Self {
        value.to_string()
    }
}
impl FromStr for AccountId {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self> {
        if value.len() > 44 {
            return Err(Error::Invalid("account address too long"));
        }
        let bytes: [u8; 32] = value
            .from_base58()
            .map_err(|_| Error::Invalid("invalid base58 account"))?
            .try_into()
            .map_err(|_| Error::Invalid("account must contain 32 bytes"))?;
        let account = Self(bytes);
        if account.to_string() != value {
            return Err(Error::Invalid("noncanonical account"));
        }
        Ok(account)
    }
}
impl TryFrom<String> for AccountId {
    type Error = Error;
    fn try_from(value: String) -> Result<Self> {
        value.parse()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShardSelector {
    pub account_id: AccountId,
    pub program_account_id: AccountId,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountData {
    pub shards: BTreeMap<AccountId, Vec<u8>>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountView {
    pub nonce: u128,
    pub data: AccountData,
}
impl AccountView {
    pub fn validate_projection(&self, selector: &ShardSelector) -> Result<()> {
        if self.data.shards.len() > 1
            || self.data.shards.iter().any(|(id, data)| {
                *id != selector.program_account_id || data.len() > MAX_SHARD_BYTES
            })
        {
            return Err(Error::Invalid("unexpected or oversized account shard"));
        }
        Ok(())
    }
    /// Call only on a native-shard projection. Zero is canonically an empty shard.
    pub fn native_balance(&self) -> Result<u128> {
        if self.data.shards.keys().any(|key| *key != NATIVE_PROGRAM) {
            return Err(Error::Invalid(
                "native balance requires the native shard projection",
            ));
        }
        let bytes = self
            .data
            .shards
            .get(&NATIVE_PROGRAM)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if bytes.is_empty() {
            return Ok(0);
        }
        let balance = u128::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| Error::Invalid("invalid native balance length"))?,
        );
        if balance == 0 {
            return Err(Error::Invalid("noncanonical zero native balance"));
        }
        Ok(balance)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeeQuote {
    pub height: u64,
    pub base_fee_exec: u64,
    pub base_fee_stor: u64,
    pub next_base_fee_exec_floor: u64,
    pub next_base_fee_exec_ceiling: u64,
    pub next_base_fee_stor_floor: u64,
    pub next_base_fee_stor_ceiling: u64,
    pub max_gas_exec: u64,
    pub max_gas_stor: u64,
}
impl FeeQuote {
    pub fn validate(&self) -> Result<()> {
        if self.next_base_fee_exec_floor > self.next_base_fee_exec_ceiling
            || self.next_base_fee_stor_floor > self.next_base_fee_stor_ceiling
            || self.max_gas_exec == 0
            || self.max_gas_stor == 0
        {
            return Err(Error::Invalid("inconsistent fee quote"));
        }
        Ok(())
    }
}

pub struct Node {
    endpoint: String,
    agent: ureq::Agent,
}
impl Node {
    pub fn new(endpoint: &str) -> Result<Self> {
        let url: ureq::http::Uri = endpoint
            .parse()
            .map_err(|_| Error::Invalid("invalid endpoint"))?;
        if !matches!(url.scheme_str(), Some("http" | "https"))
            || url.authority().is_none()
            || endpoint.contains(['@', '?', '#'])
        {
            return Err(Error::Invalid(
                "expected HTTP(S) endpoint without credentials, query or fragment",
            ));
        }
        Ok(Self {
            endpoint: endpoint.trim_end_matches('/').into(),
            agent: ureq::Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(20)))
                .max_redirects(0)
                .build()
                .into(),
        })
    }
    fn read<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let envelope: Value = self
            .agent
            .post(&self.endpoint)
            .send_json(json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .map_err(|error| Error::Transport(error.to_string()))?
            .body_mut()
            .with_config()
            .limit(1024 * 1024)
            .read_json()
            .map_err(|error| Error::Transport(error.to_string()))?;
        if envelope.get("jsonrpc") != Some(&json!("2.0"))
            || envelope.get("id") != Some(&json!(1))
            || envelope.get("error").is_some()
        {
            return Err(Error::Invalid("invalid or unsuccessful RPC envelope"));
        }
        Ok(serde_json::from_value(
            envelope
                .get("result")
                .cloned()
                .ok_or(Error::Invalid("missing RPC result"))?,
        )?)
    }
    pub fn program_ids(&self) -> Result<BTreeMap<String, [u32; 8]>> {
        let ids: BTreeMap<String, [u32; 8]> = self.read("getProgramIds", json!([]))?;
        if ids.is_empty()
            || ids.len() > 32
            || ids.keys().any(|name| name.is_empty() || name.len() > 80)
        {
            return Err(Error::Invalid("invalid program fingerprint"));
        }
        Ok(ids)
    }
    pub fn account_view(&self, selector: &ShardSelector) -> Result<AccountView> {
        let account: AccountView = self.read("getAccountView", json!([selector]))?;
        account.validate_projection(selector)?;
        Ok(account)
    }
    pub fn fee_quote(&self) -> Result<FeeQuote> {
        let quote: FeeQuote = self.read("getFeeState", json!([]))?;
        quote.validate()?;
        Ok(quote)
    }
}
