// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{Error, Reader, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use lee_core_v03::account::{AccountId, ProgramShardSelector, ShardData};
use lee_v03::PublicTransaction;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{collections::BTreeMap, time::Duration};

/// Node-reported current and next-block fee bounds; not a final fee prediction.
#[derive(Debug, Clone, serde::Serialize, Deserialize)]
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
    pub fn reserve(&self, fee: lee_v03::fees::FeeDeclaration, wire_bytes: u64) -> Result<u128> {
        self.validate()?;
        if fee.gas_limit == 0 || fee.gas_limit > self.max_gas_exec || wire_bytes > self.max_gas_stor
        {
            return Err(Error::Invalid("transaction exceeds quoted gas bounds"));
        }
        let exec = u128::from(fee.gas_limit)
            * u128::from(self.base_fee_exec.max(self.next_base_fee_exec_ceiling));
        let storage = u128::from(wire_bytes)
            * u128::from(self.base_fee_stor.max(self.next_base_fee_stor_ceiling));
        let reserve = exec
            .checked_add(storage)
            .and_then(|v| v.checked_add(u128::from(fee.tip)))
            .ok_or(Error::Invalid("fee reserve overflow"))?;
        if reserve > fee.max_fee {
            return Err(Error::Invalid(
                "fee quote exceeds approved cap; review again",
            ));
        }
        Ok(reserve)
    }
}
pub struct Node {
    endpoint: String,
    agent: ureq::Agent,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct View {
    nonce: u128,
    data: Data,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Data {
    shards: BTreeMap<AccountId, Vec<u8>>,
}
impl Node {
    pub fn new(endpoint: &str) -> Result<Self> {
        let uri: ureq::http::Uri = endpoint
            .parse()
            .map_err(|_| Error::Invalid("RPC endpoint"))?;
        if !matches!(uri.scheme_str(), Some("http" | "https"))
            || uri.authority().is_none()
            || endpoint.contains(['@', '?', '#'])
        {
            return Err(Error::Invalid(
                "HTTP(S) RPC without credentials/query required",
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
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
    fn read<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let envelope: Value = self
            .agent
            .post(&self.endpoint)
            .send_json(json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .map_err(|e| Error::Transport(e.to_string()))?
            .body_mut()
            .with_config()
            .limit(1024 * 1024)
            .read_json()
            .map_err(|e| Error::Transport(e.to_string()))?;
        if envelope.get("jsonrpc") != Some(&json!("2.0"))
            || envelope.get("id") != Some(&json!(1))
            || envelope.get("error").is_some()
        {
            return Err(Error::Invalid("invalid or failed RPC envelope"));
        }
        serde_json::from_value(
            envelope
                .get("result")
                .cloned()
                .ok_or(Error::Invalid("missing RPC result"))?,
        )
        .map_err(|_| Error::Invalid("unexpected RPC result"))
    }
    pub fn fee_quote(&self) -> Result<FeeQuote> {
        let quote: FeeQuote = self.read("getFeeState", json!([]))?;
        quote.validate()?;
        Ok(quote)
    }
    pub fn native_balance(&self, account: AccountId) -> Result<u128> {
        let selector = ProgramShardSelector::native_balance(account);
        let mut view = self.view(selector)?;
        let bytes = view
            .data
            .shards
            .remove(&selector.program_account_id)
            .unwrap_or_default();
        if bytes.is_empty() {
            return Ok(0);
        }
        let balance = u128::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| Error::Invalid("native balance length"))?,
        );
        if balance == 0 {
            return Err(Error::Invalid("noncanonical zero native balance"));
        }
        Ok(balance)
    }
    fn view(&self, selector: ProgramShardSelector) -> Result<View> {
        let view: View = self.read("getAccountView", json!([selector]))?;
        if view.data.shards.len() > 1
            || view
                .data
                .shards
                .iter()
                .any(|(id, bytes)| *id != selector.program_account_id || bytes.len() > 100 * 1024)
        {
            return Err(Error::Invalid("unexpected/oversized projected shard"));
        }
        Ok(view)
    }
    /// Broadcast already-reviewed signed bytes exactly once. Caller MUST persist them and
    /// their hash first; any transport error leaves submission uncertain. Never auto-retry.
    pub fn broadcast(&self, transaction: &PublicTransaction) -> Result<[u8; 32]> {
        let wire = wire(transaction)?;
        let hash: String = self.read("sendTransaction", json!([STANDARD.encode(wire)]))?;
        if hash != hex::encode(transaction.hash()) {
            return Err(Error::Invalid("submission hash mismatch"));
        }
        Ok(transaction.hash())
    }
    /// Exact saved-byte observation, not independent consensus finality.
    pub fn observed(&self, transaction: &PublicTransaction) -> Result<bool> {
        let result: Option<(String, u64)> =
            self.read("getTransaction", json!([hex::encode(transaction.hash())]))?;
        let Some((encoded, _)) = result else {
            return Ok(false);
        };
        let expected = wire(transaction)?;
        if encoded.len() > expected.len().div_ceil(3) * 4 {
            return Err(Error::Invalid("oversized observed transaction"));
        }
        let actual = STANDARD
            .decode(encoded)
            .map_err(|_| Error::Invalid("transaction encoding"))?;
        if actual != expected {
            return Err(Error::Invalid(
                "observed bytes differ from saved transaction",
            ));
        }
        Ok(true)
    }
}
fn wire(transaction: &PublicTransaction) -> Result<Vec<u8>> {
    let mut bytes = vec![0];
    bytes.extend(
        borsh::to_vec(transaction).map_err(|_| Error::Invalid("signed transaction encoding"))?,
    );
    if bytes.len() > 512 * 1024 {
        return Err(Error::Invalid("transaction exceeds SDK wire limit"));
    }
    Ok(bytes)
}
impl Reader for Node {
    fn shard(&self, selector: ProgramShardSelector) -> Result<ShardData> {
        let mut view = self.view(selector)?;
        view.data
            .shards
            .remove(&selector.program_account_id)
            .unwrap_or_default()
            .try_into()
            .map_err(|_| Error::Invalid("shard limit"))
    }
    fn nonce(&self, account: AccountId) -> Result<u128> {
        Ok(self
            .view(ProgramShardSelector::native_balance(account))?
            .nonce)
    }
}

#[cfg(test)]
mod fee_tests {
    use super::*;
    use lee_v03::fees::FeeDeclaration;
    #[test]
    fn fee_bounds_include_storage_tip_and_reject_bad_caps() {
        let mut quote = FeeQuote {
            height: 1,
            base_fee_exec: 2,
            base_fee_stor: 3,
            next_base_fee_exec_floor: 1,
            next_base_fee_exec_ceiling: 4,
            next_base_fee_stor_floor: 1,
            next_base_fee_stor_ceiling: 2,
            max_gas_exec: 100,
            max_gas_stor: 1000,
        };
        let fee = FeeDeclaration::new(AccountId::new([1; 32]), 10, 7, 347);
        assert_eq!(quote.reserve(fee, 100).unwrap(), 347);
        assert!(
            quote
                .reserve(
                    FeeDeclaration {
                        max_fee: 346,
                        ..fee
                    },
                    100
                )
                .is_err()
        );
        assert!(
            quote
                .reserve(
                    FeeDeclaration {
                        gas_limit: 101,
                        ..fee
                    },
                    100
                )
                .is_err()
        );
        assert!(quote.reserve(fee, 1001).is_err());
        quote.next_base_fee_exec_floor = 5;
        assert!(quote.reserve(fee, 100).is_err());
    }
    #[test]
    fn fee_reserve_overflow_is_not_wrapped() {
        let quote = FeeQuote {
            height: 1,
            base_fee_exec: u64::MAX,
            base_fee_stor: u64::MAX,
            next_base_fee_exec_floor: 1,
            next_base_fee_exec_ceiling: u64::MAX,
            next_base_fee_stor_floor: 1,
            next_base_fee_stor_ceiling: u64::MAX,
            max_gas_exec: u64::MAX,
            max_gas_stor: u64::MAX,
        };
        assert!(
            quote
                .reserve(
                    FeeDeclaration::new(AccountId::new([1; 32]), u64::MAX, 0, u128::MAX),
                    u64::MAX
                )
                .is_err()
        );
    }
}
