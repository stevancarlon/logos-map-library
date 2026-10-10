// SPDX-License-Identifier: MIT OR Apache-2.0
//! Trusted host registration review and encrypted save-before-submit recovery.
//! Kept separate from the keyless SDK. No background signing or resubmission.
pub mod native;
use lee_core_v03::account::AccountId;
use lee_v03::{
    PrivateKey, PublicKey, PublicTransaction,
    fees::FeeDeclaration,
    public_transaction::{Message, WitnessSet},
};
use logos_maps_v03_sdk::{
    Instruction, Reader, Registry,
    rpc::{FeeQuote, Node},
};
use logos_wallet_store::Store;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Registry(#[from] logos_maps_v03_sdk::Error),
    #[error(transparent)]
    Store(#[from] logos_wallet_store::Error),
    #[error("Invalid map publication: {0}")]
    Invalid(&'static str),
}
pub type Result<T> = std::result::Result<T, Error>;
pub trait Network: Reader {
    fn endpoint(&self) -> &str;
    fn fee_quote(&self) -> logos_maps_v03_sdk::Result<FeeQuote>;
    fn native_balance(&self, account: AccountId) -> logos_maps_v03_sdk::Result<u128>;
    fn broadcast(&self, transaction: &PublicTransaction) -> logos_maps_v03_sdk::Result<[u8; 32]>;
    fn observed(&self, transaction: &PublicTransaction) -> logos_maps_v03_sdk::Result<bool>;
}
impl Network for Node {
    fn fee_quote(&self) -> logos_maps_v03_sdk::Result<FeeQuote> {
        self.fee_quote()
    }
    fn native_balance(&self, account: AccountId) -> logos_maps_v03_sdk::Result<u128> {
        self.native_balance(account)
    }

    fn endpoint(&self) -> &str {
        self.endpoint()
    }
    fn broadcast(&self, tx: &PublicTransaction) -> logos_maps_v03_sdk::Result<[u8; 32]> {
        self.broadcast(tx)
    }
    fn observed(&self, tx: &PublicTransaction) -> logos_maps_v03_sdk::Result<bool> {
        self.observed(tx)
    }
}
#[derive(Serialize)]
pub struct Review {
    pub endpoint: String,
    pub program: String,
    pub author: String,
    pub instruction: serde_json::Value,
    pub nonce: String,
    /// Full fee declaration and witness-bound message encoded without rounding u128 values.
    pub message_borsh_hex: String,
    pub fee: serde_json::Value,
    pub quoted_reserve: String,
    pub quote_height: String,
    pub payer_balance: String,
    pub wire_bytes: String,
    pub expires_at_ms: u64,
    pub digest: String,
}
/// Non-cloneable one-use review, constructed only from the typed SDK preparation path.
pub struct Proposal {
    review: Review,
    instruction: Instruction,
    author: AccountId,
    program: AccountId,
    message: Message,
    fee: FeeDeclaration,
    wire_bytes: u64,
}
impl Proposal {
    pub fn review(&self) -> &Review {
        &self.review
    }
}
pub fn prepare<N: Network>(
    registry: &Registry<N>,
    author: AccountId,
    instruction: Instruction,
    fee: FeeDeclaration,
    now_ms: u64,
) -> Result<Proposal> {
    let message = registry.prepare(author, &instruction, fee)?;
    let bytes = borsh::to_vec(&message).map_err(|_| Error::Invalid("message encoding"))?;
    // The pinned public wire tag adds one byte. One Schnorr witness adds 96 bytes
    // to the existing empty vector header. Check the exact signed size before send.
    let unsigned = PublicTransaction::new(message.clone(), WitnessSet::from_raw_parts(vec![]));
    let wire_bytes = u64::try_from(
        borsh::to_vec(&unsigned)
            .map_err(|_| Error::Invalid("message encoding"))?
            .len(),
    )
    .map_err(|_| Error::Invalid("message size"))?
    .checked_add(97)
    .ok_or(Error::Invalid("message size"))?;
    let quote = registry.reader.fee_quote()?;
    let reserve = quote.reserve(fee, wire_bytes)?;
    let balance = registry.reader.native_balance(author)?;
    if balance < fee.max_fee {
        return Err(Error::Invalid(
            "insufficient balance for approved maximum fee",
        ));
    }
    let expires_at_ms = now_ms
        .checked_add(120_000)
        .ok_or(Error::Invalid("clock overflow"))?;
    let endpoint = registry.reader.endpoint().to_owned();
    let mut digest = Sha256::new();
    digest.update(b"logos-maps-review-v1\0");
    digest.update((endpoint.len() as u64).to_le_bytes());
    digest.update(endpoint.as_bytes());
    digest.update(expires_at_ms.to_le_bytes());
    digest.update(&bytes);
    let review = Review {
        endpoint,
        program: registry.program.to_string(),
        author: author.to_string(),
        instruction: serde_json::to_value(&instruction)
            .map_err(|_| Error::Invalid("instruction encoding"))?,
        nonce: message.nonces[0].0.to_string(),
        message_borsh_hex: hex::encode(bytes),
        fee: serde_json::json!({"payer":fee.payer.to_string(),"gas_limit":fee.gas_limit.to_string(),"tip":fee.tip.to_string(),"max_fee":fee.max_fee.to_string()}),
        quoted_reserve: reserve.to_string(),
        quote_height: quote.height.to_string(),
        payer_balance: balance.to_string(),
        wire_bytes: wire_bytes.to_string(),
        expires_at_ms,
        digest: hex::encode(digest.finalize()),
    };
    Ok(Proposal {
        review,
        instruction,
        author,
        program: registry.program,
        message,
        fee,
        wire_bytes,
    })
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Saved before any I/O; a crash or transport error may leave inclusion unknown.
    SubmissionUnknown,
    Acknowledged,
    /// Exact signed bytes observed, not proof of execution success or consensus finality.
    Observed,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub hash: String,
    pub endpoint: String,
    pub author: String,
    pub program: String,
    pub review_digest: String,
    pub status: Status,
    transaction: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    format: String,
    submissions: Vec<Submission>,
}
pub struct Publisher {
    store: Store,
}
fn encode(value: &Payload) -> Result<Zeroizing<Vec<u8>>> {
    serde_json::to_vec(value)
        .map(Zeroizing::new)
        .map_err(|_| Error::Invalid("outbox encoding"))
}
impl Publisher {
    pub fn create(path: &Path, password: &[u8]) -> Result<Self> {
        let payload = Payload {
            format: "logos-maps-outbox-v1".into(),
            submissions: vec![],
        };
        Ok(Self {
            store: Store::create(path, password, &encode(&payload)?)?,
        })
    }
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            store: Store::open(path)?,
        })
    }
    fn load(&self, password: &[u8]) -> Result<(u64, Payload)> {
        let snapshot = self.store.load(password)?;
        let payload: Payload = serde_json::from_slice(&snapshot.payload)
            .map_err(|_| Error::Invalid("outbox schema"))?;
        if payload.format != "logos-maps-outbox-v1" || payload.submissions.len() > 128 {
            return Err(Error::Invalid("outbox format or capacity"));
        }
        for row in &payload.submissions {
            decode(row)?;
        }
        Ok((snapshot.revision, payload))
    }
    pub fn submissions(&self, password: &[u8]) -> Result<Vec<Submission>> {
        Ok(self.load(password)?.1.submissions)
    }
    /// Invoke only after explicit approval of `proposal.review()`. Consumes the proposal.
    /// Rechecks exact witnesses/nonce. Never silently refreshes the approved transaction.
    /// The supplied key remains owned by the trusted calling host, never by the SDK/UI.
    pub fn approve<N: Network>(
        &mut self,
        password: &[u8],
        registry: &Registry<N>,
        proposal: Proposal,
        key: &PrivateKey,
        now_ms: u64,
    ) -> Result<Submission> {
        if now_ms >= proposal.review.expires_at_ms
            || now_ms < proposal.review.expires_at_ms.saturating_sub(120_000)
            || registry.program != proposal.program
            || registry.reader.endpoint() != proposal.review.endpoint
            || AccountId::from(&PublicKey::new_from_private_key(key)) != proposal.author
        {
            return Err(Error::Invalid("expired or mismatched approval context"));
        }
        let fresh = registry.prepare(proposal.author, &proposal.instruction, proposal.fee)?;
        if borsh::to_vec(&fresh).map_err(|_| Error::Invalid("message encoding"))?
            != borsh::to_vec(&proposal.message).map_err(|_| Error::Invalid("message encoding"))?
        {
            return Err(Error::Invalid("registry or nonce changed; review again"));
        }
        registry
            .reader
            .fee_quote()?
            .reserve(proposal.fee, proposal.wire_bytes)?;
        if registry.reader.native_balance(proposal.author)? < proposal.fee.max_fee {
            return Err(Error::Invalid(
                "balance no longer covers approved maximum fee",
            ));
        }
        let (revision, mut payload) = self.load(password)?;
        if payload.submissions.len() >= 128 {
            return Err(Error::Invalid("outbox full"));
        }
        if payload.submissions.iter().any(|s| {
            s.endpoint == proposal.review.endpoint
                && s.author == proposal.review.author
                && s.status != Status::Observed
        }) {
            return Err(Error::Invalid(
                "reconcile the author's pending submission first",
            ));
        }
        let witnesses = WitnessSet::for_message(&proposal.message, &[key]);
        if !witnesses.is_valid_for(&proposal.message) {
            return Err(Error::Invalid("invalid signing witness"));
        }
        let tx = PublicTransaction::new(proposal.message, witnesses);
        if borsh::to_vec(&tx)
            .map_err(|_| Error::Invalid("signed encoding"))?
            .len() as u64
            + 1
            != proposal.wire_bytes
        {
            return Err(Error::Invalid("signed size differs from fee review"));
        }
        let mut row = Submission {
            hash: hex::encode(tx.hash()),
            endpoint: proposal.review.endpoint,
            author: proposal.review.author,
            program: proposal.review.program,
            review_digest: proposal.review.digest,
            status: Status::SubmissionUnknown,
            transaction: borsh::to_vec(&tx).map_err(|_| Error::Invalid("signed encoding"))?,
        };
        if payload.submissions.iter().any(|s| s.hash == row.hash) {
            return Err(Error::Invalid("transaction already saved"));
        }
        payload.submissions.push(row.clone());
        // A save conflict/error exits before the only broadcast call.
        let next_revision = self.store.save(password, revision, &encode(&payload)?)?;
        if registry
            .reader
            .broadcast(&tx)
            .is_ok_and(|hash| hex::encode(hash) == row.hash)
        {
            payload.submissions.last_mut().unwrap().status = Status::Acknowledged;
            // If this save fails, the durable pre-send row still holds the exact recovery hash.
            if self
                .store
                .save(password, next_revision, &encode(&payload)?)
                .is_ok()
            {
                row.status = Status::Acknowledged;
            }
        }
        Ok(row)
    }
    /// Read-only network reconciliation. Never sends the saved transaction again.
    pub fn reconcile<N: Network>(
        &mut self,
        password: &[u8],
        network: &N,
        hash: &str,
    ) -> Result<Submission> {
        let (revision, mut payload) = self.load(password)?;
        let row = payload
            .submissions
            .iter_mut()
            .find(|s| s.hash == hash)
            .ok_or(Error::Invalid("unknown saved hash"))?;
        if row.endpoint != network.endpoint() {
            return Err(Error::Invalid("recovery endpoint mismatch"));
        }
        if row.status != Status::Observed && network.observed(&decode(row)?)? {
            row.status = Status::Observed;
        }
        let result = row.clone();
        self.store.save(password, revision, &encode(&payload)?)?;
        Ok(result)
    }
}
fn decode(row: &Submission) -> Result<PublicTransaction> {
    if row.transaction.len() > 256 * 1024 {
        return Err(Error::Invalid("oversized saved transaction"));
    }
    let tx: PublicTransaction = borsh::from_slice(&row.transaction)
        .map_err(|_| Error::Invalid("saved transaction encoding"))?;
    if tx.message.program_account_id.to_string() != row.program
        || tx
            .message
            .fee
            .is_none_or(|fee| fee.payer.to_string() != row.author)
        || !tx.witness_set.is_valid_for(&tx.message)
        || !lee_v03::is_fee_authorized(&tx.message, &tx.witness_set)
        || hex::encode(tx.hash()) != row.hash
    {
        return Err(Error::Invalid("saved hash mismatch"));
    }
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lee_core_v03::account::{ProgramShardSelector, ShardData};
    use std::cell::Cell;
    struct Fake {
        url: String,
        nonce: Cell<u128>,
        sends: Cell<usize>,
        seen: Cell<bool>,
        fail: bool,
        price: Cell<u64>,
        balance: Cell<u128>,
        path: std::path::PathBuf,
    }
    impl Reader for Fake {
        fn shard(&self, _: ProgramShardSelector) -> logos_maps_v03_sdk::Result<ShardData> {
            Ok(Default::default())
        }
        fn nonce(&self, _: AccountId) -> logos_maps_v03_sdk::Result<u128> {
            Ok(self.nonce.get())
        }
    }
    impl Network for Fake {
        fn fee_quote(&self) -> logos_maps_v03_sdk::Result<FeeQuote> {
            Ok(FeeQuote {
                height: 1,
                base_fee_exec: self.price.get(),
                base_fee_stor: 1,
                next_base_fee_exec_floor: 1,
                next_base_fee_exec_ceiling: self.price.get(),
                next_base_fee_stor_floor: 1,
                next_base_fee_stor_ceiling: 1,
                max_gas_exec: 100_000_000,
                max_gas_stor: 1_000_000,
            })
        }
        fn native_balance(&self, _: AccountId) -> logos_maps_v03_sdk::Result<u128> {
            Ok(self.balance.get())
        }

        fn endpoint(&self) -> &str {
            &self.url
        }
        fn broadcast(&self, tx: &PublicTransaction) -> logos_maps_v03_sdk::Result<[u8; 32]> {
            // Inspect a separately opened store DURING broadcast, proving durability first.
            let publisher = Publisher::open(&self.path).unwrap();
            let rows = publisher.submissions(b"fixture password").unwrap();
            assert_eq!(rows.last().unwrap().hash, hex::encode(tx.hash()));
            assert_eq!(rows.last().unwrap().transaction, borsh::to_vec(tx).unwrap());
            assert_eq!(rows.last().unwrap().status, Status::SubmissionUnknown);
            self.sends.set(self.sends.get() + 1);
            if self.fail {
                Err(logos_maps_v03_sdk::Error::Transport(
                    "simulated lost response".into(),
                ))
            } else {
                Ok(tx.hash())
            }
        }
        fn observed(&self, _: &PublicTransaction) -> logos_maps_v03_sdk::Result<bool> {
            Ok(self.seen.get())
        }
    }
    fn fixture(path: &Path, fail: bool) -> (Registry<Fake>, PrivateKey) {
        (
            Registry {
                program: AccountId::new([3; 32]),
                reader: Fake {
                    url: "http://127.0.0.1:3040".into(),
                    nonce: Cell::new(1),
                    sends: Cell::new(0),
                    seen: Cell::new(false),
                    fail,
                    price: Cell::new(1),
                    balance: Cell::new(10_000_000_000),
                    path: path.into(),
                },
            },
            PrivateKey::try_new([1; 32]).unwrap(),
        )
    }
    fn proposal(registry: &Registry<Fake>, key: &PrivateKey) -> Proposal {
        let author = AccountId::from(&PublicKey::new_from_private_key(key));
        prepare(
            registry,
            author,
            Instruction::Initialize,
            FeeDeclaration::new(author, 10_000_000, 0, 500_000_000),
            1000,
        )
        .unwrap()
    }
    #[test]
    fn saved_before_submission_and_recovered_without_resend() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outbox.sqlite");
        let (registry, key) = fixture(&path, true);
        let mut publisher = Publisher::create(&path, b"fixture password").unwrap();
        let row = publisher
            .approve(
                b"fixture password",
                &registry,
                proposal(&registry, &key),
                &key,
                1001,
            )
            .unwrap();
        assert_eq!(row.status, Status::SubmissionUnknown);
        assert_eq!(registry.reader.sends.get(), 1);
        assert!(
            publisher
                .approve(
                    b"fixture password",
                    &registry,
                    proposal(&registry, &key),
                    &key,
                    1002
                )
                .is_err()
        );
        drop(publisher);
        let mut publisher = Publisher::open(&path).unwrap();
        assert!(publisher.submissions(b"wrong password").is_err());
        assert_eq!(
            publisher
                .reconcile(b"fixture password", &registry.reader, &row.hash)
                .unwrap()
                .status,
            Status::SubmissionUnknown
        );
        registry.reader.seen.set(true);
        assert_eq!(
            publisher
                .reconcile(b"fixture password", &registry.reader, &row.hash)
                .unwrap()
                .status,
            Status::Observed
        );
        assert_eq!(registry.reader.sends.get(), 1);
        drop(publisher);
        assert_eq!(
            Publisher::open(&path)
                .unwrap()
                .submissions(b"fixture password")
                .unwrap()[0]
                .status,
            Status::Observed
        );
        assert!(
            !std::fs::read(&path)
                .unwrap()
                .windows(row.hash.len())
                .any(|v| v == row.hash.as_bytes())
        );
    }
    #[test]
    fn stale_nonce_expiry_endpoint_and_key_never_send() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outbox.sqlite");
        let (mut registry, key) = fixture(&path, false);
        let mut publisher = Publisher::create(&path, b"fixture password").unwrap();
        let p = proposal(&registry, &key);
        registry.reader.nonce.set(2);
        assert!(
            publisher
                .approve(b"fixture password", &registry, p, &key, 1001)
                .is_err()
        );
        assert!(
            publisher
                .approve(
                    b"fixture password",
                    &registry,
                    proposal(&registry, &key),
                    &key,
                    121000
                )
                .is_err()
        );
        let p = proposal(&registry, &key);
        registry.reader.url = "http://127.0.0.1:3041".into();
        assert!(
            publisher
                .approve(b"fixture password", &registry, p, &key, 1001)
                .is_err()
        );
        let other = PrivateKey::try_new([2; 32]).unwrap();
        assert!(
            publisher
                .approve(
                    b"fixture password",
                    &registry,
                    proposal(&registry, &key),
                    &other,
                    1001
                )
                .is_err()
        );
        assert!(
            publisher
                .approve(
                    b"wrong password",
                    &registry,
                    proposal(&registry, &key),
                    &key,
                    1001
                )
                .is_err()
        );
        assert_eq!(registry.reader.sends.get(), 0);
        assert!(
            publisher
                .submissions(b"fixture password")
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn changed_fee_or_balance_requires_a_new_review_without_sending() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outbox.sqlite");
        let (registry, key) = fixture(&path, false);
        let mut publisher = Publisher::create(&path, b"fixture password").unwrap();
        let p = proposal(&registry, &key);
        assert!(p.review().quoted_reserve.parse::<u128>().unwrap() > 10_000_000);
        registry.reader.price.set(100);
        assert!(
            publisher
                .approve(b"fixture password", &registry, p, &key, 1001)
                .is_err()
        );
        registry.reader.price.set(1);
        let p = proposal(&registry, &key);
        registry.reader.balance.set(0);
        assert!(
            publisher
                .approve(b"fixture password", &registry, p, &key, 1001)
                .is_err()
        );
        assert_eq!(registry.reader.sends.get(), 0);
        assert!(
            publisher
                .submissions(b"fixture password")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn acknowledgement_is_not_observation_and_existing_store_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outbox.sqlite");
        let (mut registry, key) = fixture(&path, false);
        let mut publisher = Publisher::create(&path, b"fixture password").unwrap();
        assert!(Publisher::create(&path, b"new password").is_err());
        let row = publisher
            .approve(
                b"fixture password",
                &registry,
                proposal(&registry, &key),
                &key,
                1001,
            )
            .unwrap();
        assert_eq!(row.status, Status::Acknowledged);
        assert_eq!(
            publisher
                .reconcile(b"fixture password", &registry.reader, &row.hash)
                .unwrap()
                .status,
            Status::Acknowledged
        );
        registry.reader.url = "http://127.0.0.1:3041".into();
        assert!(
            publisher
                .reconcile(b"fixture password", &registry.reader, &row.hash)
                .is_err()
        );
        assert_eq!(registry.reader.sends.get(), 1);
    }
}
