// SPDX-License-Identifier: MIT OR Apache-2.0
//! Versioned public transfer requests. Only trusted owner dispatch can decide.
use crate::{
    AccountId, Error, Result,
    outbox::{Outbox, SubmissionNode},
    token::{PreparedTokenTransfer, TokenKind, TokenReader, TokenTransfer, TokenWallet},
    transfer::{NativeTransfer, PreparedTransfer, Wallet},
};
use logos_wallet_policy::{Prompt, Request, principal::Principal};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Asset {
    Native,
    Fungible { definition: AccountId },
    NftMaster { definition: AccountId },
    NftCopy { definition: AccountId },
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub network: String,
    pub from: AccountId,
    pub to: AccountId,
    pub asset: Asset,
    pub amount: String,
    pub gas_limit: String,
    pub tip: String,
    pub max_fee: String,
}
fn number<T: std::str::FromStr>(value: &str) -> Result<T> {
    if value.is_empty()
        || value.len() > 39
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(Error::Invalid(
            "amounts and fees must be canonical decimal strings",
        ));
    }
    value
        .parse()
        .map_err(|_| Error::Invalid("amount or fee exceeds integer range"))
}
enum Prepared {
    Native(PreparedTransfer),
    Token(PreparedTokenTransfer),
}
impl Prepared {
    fn prompt(&self) -> &Prompt {
        match self {
            Self::Native(p) => p.prompt(),
            Self::Token(p) => p.prompt(),
        }
    }
}
enum Phase {
    Pending(Box<Prepared>),
    Rejected,
    Failed(String),
    Cancelled,
}
struct Entry {
    principal: Principal,
    proposal: Proposal,
    expires_at: u64,
    phase: Phase,
}
#[derive(Default)]
pub(crate) struct Requests {
    entries: BTreeMap<String, Entry>,
}
impl Requests {
    fn prune(&mut self, now: u64) {
        self.entries.retain(|_, e| e.expires_at > now);
    }
    pub fn clear(&mut self) {
        self.entries.clear();
    }
    /// Outbox mutations invalidate all one-use approvals, even those for other apps.
    pub fn invalidate_principal(&mut self, principal: &Principal) {
        for entry in self.entries.values_mut() {
            if &entry.principal == principal && matches!(entry.phase, Phase::Pending(_)) {
                entry.phase = Phase::Cancelled;
            }
        }
    }
    pub fn invalidate(&mut self) {
        for entry in self.entries.values_mut() {
            if matches!(entry.phase, Phase::Pending(_)) {
                entry.phase = Phase::Cancelled;
            }
        }
    }
    pub fn propose(
        &mut self,
        store: &mut Outbox,
        caller: &Principal,
        node: &(impl TokenReader + SubmissionNode),
        mut proposal: Proposal,
        now: u64,
    ) -> Result<String> {
        self.prune(now);
        if self.entries.len() >= 64
            || self
                .entries
                .values()
                .filter(|e| &e.principal == caller)
                .count()
                >= 8
        {
            return Err(Error::Invalid("transaction request limit reached"));
        }
        proposal.network = proposal.network.trim_end_matches('/').into();
        if proposal.network != node.endpoint() {
            return Err(Error::Invalid(
                "requested network differs from owner configuration",
            ));
        }
        let amount = number(&proposal.amount)?;
        let gas_limit = number(&proposal.gas_limit)?;
        let tip = number(&proposal.tip)?;
        let max_fee = number(&proposal.max_fee)?;
        let mut random = [0; 16];
        OsRng
            .try_fill_bytes(&mut random)
            .map_err(|_| Error::Invalid("OS randomness unavailable"))?;
        let id = hex::encode(random);
        if self.entries.contains_key(&id) {
            return Err(Error::Invalid("duplicate transaction request ID"));
        }
        let prepared = match proposal.asset {
            Asset::Native => Prepared::Native(store.prepare_native(
                caller,
                &Wallet::new(node, node.endpoint())?,
                NativeTransfer {
                    from: proposal.from,
                    to: proposal.to,
                    amount,
                    gas_limit,
                    tip,
                    max_fee,
                },
                now,
            )?),
            ref asset => {
                let (definition, kind) = match asset {
                    Asset::Fungible { definition } => (*definition, TokenKind::Fungible),
                    Asset::NftMaster { definition } => (*definition, TokenKind::NftMaster),
                    Asset::NftCopy { definition } => (*definition, TokenKind::NftPrintedCopy),
                    Asset::Native => unreachable!(),
                };
                Prepared::Token(store.prepare_token(
                    caller,
                    &TokenWallet::new(node, node.endpoint())?,
                    TokenTransfer {
                        from: proposal.from,
                        to: proposal.to,
                        definition,
                        kind,
                        amount,
                        gas_limit,
                        tip,
                        max_fee,
                    },
                    now,
                )?)
            }
        };
        let expires_at = prepared.prompt().expires_at;
        self.entries.insert(
            id.clone(),
            Entry {
                principal: caller.clone(),
                proposal,
                expires_at,
                phase: Phase::Pending(Box::new(prepared)),
            },
        );
        Ok(id)
    }
    pub fn reviews(&mut self, now: u64) -> Vec<Value> {
        self.prune(now);
        self.entries.iter().filter_map(|(id,entry)|{
            let Phase::Pending(prepared)=&entry.phase else {return None};
            let Request::Transaction(transaction)=&prepared.prompt().request else {return None};
            Some(json!({"id":id,"principal":entry.principal,"proposal":entry.proposal,
                "expires_at":entry.expires_at,"approval_digest":hex::encode(transaction.message_hash),"effects":transaction.effects,
                "fee_notice":"Fees may still be charged if execution fails. Sequencer inclusion alone does not prove successful execution or independent finality."}))
        }).collect()
    }
    pub fn status(
        &mut self,
        store: &Outbox,
        caller: &Principal,
        id: &str,
        now: u64,
    ) -> Result<Value> {
        self.prune(now);
        // Durable submission wins even if recording its acknowledgement failed.
        if let Some(status) = store.status_optional(caller, id)? {
            return Ok(
                json!({"id":id,"state":"submitted_record","transaction":status,"execution_outcome":"unknown"}),
            );
        }
        let entry = self
            .entries
            .get(id)
            .filter(|e| &e.principal == caller)
            .ok_or(Error::Invalid("transaction request missing or expired"))?;
        Ok(match &entry.phase {
            Phase::Pending(_) => json!({"id":id,"state":"pending_approval"}),
            Phase::Rejected => json!({"id":id,"state":"rejected"}),
            Phase::Failed(error) => {
                json!({"id":id,"state":"failed","error":error,"retry":"Request a fresh review; this request cannot be retried."})
            }
            Phase::Cancelled => {
                json!({"id":id,"state":"cancelled","reason":"Wallet state or network changed; request a fresh review."})
            }
        })
    }
    /// Not an app method. Removes the prepared request before attempting signing.
    pub fn decide(
        &mut self,
        store: &mut Outbox,
        node: &(impl TokenReader + SubmissionNode),
        id: &str,
        approve: bool,
        now: u64,
    ) -> Result<Value> {
        self.prune(now);
        let entry = self
            .entries
            .get(id)
            .filter(|e| matches!(e.phase, Phase::Pending(_)))
            .ok_or(Error::Invalid("transaction request missing or expired"))?;
        if entry.proposal.network != node.endpoint() {
            return Err(Error::Invalid("network differs from reviewed request"));
        }
        let mut entry = self
            .entries
            .remove(id)
            .ok_or(Error::Invalid("transaction request missing"))?;
        let Phase::Pending(prepared) = std::mem::replace(
            &mut entry.phase,
            Phase::Failed("Transaction attempt did not complete".into()),
        ) else {
            unreachable!()
        };
        let result = (|| -> Result<Value> {
            store.owner_decide(prepared.prompt().id, approve, now)?;
            if !approve {
                entry.phase = Phase::Rejected;
                return Ok(json!({"id":id,"state":"rejected"}));
            }
            let status = match *prepared {
                Prepared::Native(prepared) => store.execute_native(
                    &entry.principal,
                    id,
                    &Wallet::new(node, node.endpoint())?,
                    node,
                    &prepared,
                    now,
                )?,
                Prepared::Token(prepared) => store.execute_token(
                    &entry.principal,
                    id,
                    &TokenWallet::new(node, node.endpoint())?,
                    node,
                    &prepared,
                    now,
                )?,
            };
            Ok(
                json!({"id":id,"state":"submitted_record","transaction":status,"execution_outcome":"unknown"}),
            )
        })();
        if approve {
            // Even an error can follow a committed outbox write. Cancel other
            // displayed reviews conservatively; no automatic signing retry.
            self.invalidate();
        }
        if let Err(error) = &result {
            entry.phase = Phase::Failed(error.to_string());
        }
        self.entries.insert(id.into(), entry);
        result
    }
}

#[cfg(test)]
#[path = "transactions_tests.rs"]
mod tests;
