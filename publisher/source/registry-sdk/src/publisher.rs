// SPDX-License-Identifier: MIT OR Apache-2.0
//! Signed public registry writes. Caller owns keys, approval, and nonce serialization.
//! An RPC acknowledgement is pending; confirmation checks the returned transaction hash.
use crate::{AccountReader, Error, HttpNode, Result, entry_address};
use common::{HashType, transaction::LeeTransaction};
use lee::{
    PrivateKey, PublicKey, PublicTransaction,
    public_transaction::{Message, WitnessSet},
};
use logos_prize_registry::{Instruction, Metadata};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use spel_framework::prelude::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Write {
    Initialize,
    CreatePage {
        number: u64,
    },
    Register {
        target: [u8; 32],
        page: u64,
        submitted_at: u64,
        metadata: Metadata,
    },
    Update {
        target: [u8; 32],
        expected_revision: u64,
        metadata: Metadata,
    },
}
impl Write {
    /// Exact canonical message presented to the caller's trusted signing layer.
    pub fn message(
        &self,
        registry: ProgramId,
        author: AccountId,
        nonce: lee_core::account::Nonce,
    ) -> Result<Message> {
        let catalog = compute_pda(&registry, &[&seed_from_str("registry")]);
        let (accounts, instruction) = match self {
            Self::Initialize => (vec![catalog, author], Instruction::Initialize {}),
            Self::CreatePage { number } => (
                vec![
                    compute_pda(&registry, &[&seed_from_str("page"), &number.to_seed()]),
                    author,
                ],
                Instruction::CreatePage { number: *number },
            ),
            Self::Register {
                target,
                page,
                submitted_at,
                metadata,
            } => {
                metadata
                    .validate()
                    .map_err(|e| Error::Invalid(e.to_string()))?;
                (
                    vec![
                        catalog,
                        compute_pda(&registry, &[&seed_from_str("page"), &page.to_seed()]),
                        entry_address(&registry, target, author.value()),
                        author,
                    ],
                    Instruction::Register {
                        program_id: *target,
                        page_number: *page,
                        submitted_at: *submitted_at,
                        metadata_json: serde_json::to_string(metadata).map_err(invalid)?,
                        claim_deployer: false,
                    },
                )
            }
            Self::Update {
                target,
                expected_revision,
                metadata,
            } => {
                metadata
                    .validate()
                    .map_err(|e| Error::Invalid(e.to_string()))?;
                (
                    vec![entry_address(&registry, target, author.value()), author],
                    Instruction::Update {
                        program_id: *target,
                        expected_revision: *expected_revision,
                        metadata_json: serde_json::to_string(metadata).map_err(invalid)?,
                    },
                )
            }
        };
        Message::try_new(registry, accounts, vec![nonce], instruction).map_err(invalid)
    }
}
fn invalid(e: impl std::fmt::Display) -> Error {
    Error::Invalid(e.to_string())
}
/// Read a typed signing-key vault. Password input belongs to a trusted UI; never
/// accept passwords through command-line arguments or log decrypted material.
pub fn read_signing_key(path: &std::path::Path, password: &[u8]) -> Result<PrivateKey> {
    let payload = logos_wallet_policy::vault::read_file(path, password).map_err(invalid)?;
    if payload.len() != 40 || &payload[..8] != b"REGKEY01" {
        return Err(Error::Invalid("Not a registry signing-key vault".into()));
    }
    PrivateKey::try_new(payload[8..].try_into().map_err(invalid)?)
        .map_err(|_| Error::Invalid("Invalid signing key".into()))
}
impl HttpNode {
    /// Fetches and verifies inclusion of one private commitment in the node's
    /// reported root. This discloses the commitment to this RPC, not its opening.
    pub fn commitment_membership(
        &self,
        commitment: lee_core::Commitment,
    ) -> Result<(lee_core::MembershipProof, [u8; 32])> {
        let (proofs, root): (Vec<Option<lee_core::MembershipProof>>, [u8; 32]) =
            serde_json::from_value(self.rpc("getProofsAndRoot", json!([[commitment]]))?)
                .map_err(invalid)?;
        if proofs.len() != 1 {
            return Err(Error::Invalid("Unexpected membership proof count".into()));
        }
        let proof = proofs
            .into_iter()
            .next()
            .flatten()
            .ok_or_else(|| Error::Invalid("Commitment is not included".into()))?;
        if proof.1.len() > usize::BITS as usize
            || (proof.1.len() < usize::BITS as usize && proof.0 >> proof.1.len() != 0)
            || lee_core::compute_digest_for_path(&commitment, &proof) != root
        {
            return Err(Error::Invalid("Invalid commitment membership proof".into()));
        }
        Ok((proof, root))
    }
    /// Reads a bounded private commitment snapshot. No account identifiers are sent.
    pub fn commitment_root(&self) -> Result<[u8; 32]> {
        let (proofs, root): (Vec<Option<lee_core::MembershipProof>>, [u8; 32]) =
            serde_json::from_value(self.rpc("getProofsAndRoot", json!([[]]))?).map_err(invalid)?;
        if !proofs.is_empty() {
            return Err(Error::Invalid(
                "Unexpected membership proofs for empty request".into(),
            ));
        }
        Ok(root)
    }
    pub(crate) fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        self.rpc_with_limit(method, params, 1024 * 1024)
    }
    fn rpc_with_limit(&self, method: &str, params: Value, limit: u64) -> Result<Value> {
        let value: Value = self
            .agent
            .post(&self.endpoint)
            .send_json(json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params}))
            .map_err(|e| Error::Transport(e.to_string()))?
            .body_mut()
            .with_config()
            .limit(limit)
            .read_json()
            .map_err(|e| Error::Transport(e.to_string()))?;
        if value.get("id") != Some(&json!(1))
            || value.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        {
            return Err(Error::Invalid("Invalid RPC envelope".into()));
        }
        if let Some(error) = value.get("error") {
            return Err(Error::Transport(error.to_string()));
        }
        value
            .get("result")
            .cloned()
            .ok_or_else(|| Error::Invalid("Missing RPC result".into()))
    }
    pub fn last_block_id(&self) -> Result<u64> {
        serde_json::from_value(self.rpc("getLastBlockId", json!([]))?).map_err(invalid)
    }
    /// Bounded history read with ID/content-hash integrity checking. This does
    /// not pin the sequencer signer or independently establish consensus finality.
    pub fn block(&self, id: u64) -> Result<Option<common::block::Block>> {
        let block: Option<common::block::Block> = serde_json::from_value(self.rpc_with_limit(
            "getBlock",
            json!([id]),
            16 * 1024 * 1024,
        )?)
        .map_err(invalid)?;
        if let Some(block) = &block
            && (block.header.block_id != id || block.recompute_hash() != block.header.hash)
        {
            return Err(Error::Invalid("Block ID/content hash mismatch".into()));
        }
        Ok(block)
    }
    /// Signs exactly one explicit write. Do not concurrently use the same signing account.
    pub fn sign_write(
        &self,
        registry: ProgramId,
        key: &PrivateKey,
        write: &Write,
    ) -> Result<LeeTransaction> {
        let author = AccountId::from(&PublicKey::new_from_private_key(key));
        let account = self.account(author)?;
        if account.program_owner == lee_core::program::DEFAULT_PROGRAM_ID {
            return Err(Error::Invalid(
                "Initialize the signing account in the wallet before using the registry".into(),
            ));
        }
        let message = write.message(registry, author, account.nonce)?;
        let witness = WitnessSet::for_message(&message, &[key]);
        if !witness.is_valid_for(&message) {
            return Err(Error::Invalid("Invalid signature".into()));
        }
        Ok(LeeTransaction::Public(PublicTransaction::new(
            message, witness,
        )))
    }
    /// No automatic retransmission: a timeout may mean the transaction was accepted.
    /// Keep the locally calculated hash and query confirmation before retrying.
    pub fn submit(&self, transaction: &LeeTransaction) -> Result<HashType> {
        let expected = transaction.hash();
        let received: HashType =
            serde_json::from_value(self.rpc("sendTransaction", json!([transaction]))?)
                .map_err(invalid)?;
        if received != expected {
            return Err(Error::Invalid("Submission hash mismatch".into()));
        }
        Ok(expected)
    }
    /// Sequencer inclusion, not independent consensus/finality verification.
    pub fn confirmed(&self, hash: HashType) -> Result<bool> {
        Ok(self.confirmed_transaction(hash)?.is_some())
    }
    /// Returns only the exact requested transaction after its signatures/proof
    /// have been verified. The node's inclusion claim is not consensus finality.
    pub fn confirmed_transaction(&self, hash: HashType) -> Result<Option<LeeTransaction>> {
        let value = self.rpc("getTransaction", json!([hash]))?;
        if value.is_null() {
            return Ok(None);
        }
        let (transaction, _block): (LeeTransaction, Value) =
            serde_json::from_value(value).map_err(invalid)?;
        if transaction.hash() != hash {
            return Err(Error::Invalid("Confirmation hash mismatch".into()));
        }
        if matches!(&transaction, LeeTransaction::PrivacyPreserving(_)) {
            require_real_private_receipts(std::env::var("RISC0_DEV_MODE").ok().as_deref())?;
        }
        Ok(Some(
            transaction.transaction_stateless_check().map_err(invalid)?,
        ))
    }
}
fn require_real_private_receipts(development: Option<&str>) -> Result<()> {
    if development.is_some_and(|value| value != "0") {
        return Err(Error::Invalid(
            "Development receipts cannot confirm private transactions".into(),
        ));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_confirmation_never_accepts_development_mode() {
        assert!(require_real_private_receipts(None).is_ok());
        assert!(require_real_private_receipts(Some("0")).is_ok());
        for value in ["1", "true", ""] {
            assert!(require_real_private_receipts(Some(value)).is_err());
        }
    }
    #[test]
    fn approval_message_binds_program_author_page_and_nonce() {
        let key = PrivateKey::try_new([1; 32]).unwrap();
        let author = AccountId::from(&PublicKey::new_from_private_key(&key));
        let write = Write::CreatePage { number: 3 };
        let message = write
            .message([2; 8], author, lee_core::account::Nonce(4))
            .unwrap();
        let witness = WitnessSet::for_message(&message, &[&key]);
        assert!(witness.is_valid_for(&message));
        for changed in [
            write
                .message([3; 8], author, lee_core::account::Nonce(4))
                .unwrap(),
            write
                .message([2; 8], author, lee_core::account::Nonce(5))
                .unwrap(),
            Write::CreatePage { number: 4 }
                .message([2; 8], author, lee_core::account::Nonce(4))
                .unwrap(),
            write
                .message([2; 8], AccountId::new([9; 32]), lee_core::account::Nonce(4))
                .unwrap(),
        ] {
            assert!(!witness.is_valid_for(&changed));
        }
    }
}
