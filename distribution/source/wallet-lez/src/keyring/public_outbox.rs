// SPDX-License-Identifier: MIT OR Apache-2.0
//! Public transactions are durably retained before network submission. A crash
//! after the commit cannot distinguish "not broadcast" from "reply lost";
//! reconcile the saved hash with the node, never automatically sign a replacement.
use super::{Error, Keyring, Result};
use common::{HashType, transaction::LeeTransaction};
use logos_wallet_policy::principal::Principal;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionState {
    PreparedOrSubmissionUnknown,
    Submitted,
    Uncertain,
    IncludedBySequencer,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub id: String,
    pub principal: Principal,
    pub endpoint: String,
    pub transaction: LeeTransaction,
    pub state: SubmissionState,
    #[serde(default)]
    pub last_checked_at: Option<u64>,
}
#[derive(Clone, Debug, Serialize)]
pub struct SubmissionStatus {
    pub id: String,
    pub hash: HashType,
    pub endpoint: String,
    pub state: SubmissionState,
    pub last_checked_at: Option<u64>,
}
impl Submission {
    pub fn status(&self) -> SubmissionStatus {
        SubmissionStatus {
            id: self.id.clone(),
            hash: self.transaction.hash(),
            endpoint: self.endpoint.clone(),
            state: self.state.clone(),
            last_checked_at: self.last_checked_at,
        }
    }
}
pub(super) fn validate(
    records: &[Submission],
    accounts: &BTreeSet<[u8; 32]>,
    private: &BTreeSet<[u8; 32]>,
) -> Result<()> {
    let mut ids = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    for record in records {
        record.principal.validate().map_err(|_| Error::Invalid)?;
        if record.state == SubmissionState::IncludedBySequencer && record.last_checked_at.is_none()
        {
            return Err(Error::Invalid);
        }
        if record.id.len() != 32
            || !record.id.bytes().all(|b| b.is_ascii_hexdigit())
            || !ids.insert(record.id.clone())
            || record.endpoint.is_empty()
            || record.endpoint.len() > 2048
            || !hashes.insert((record.endpoint.clone(), record.transaction.hash().0))
        {
            return Err(Error::Invalid);
        }
        let LeeTransaction::Public(tx) = &record.transaction else {
            return Err(Error::Invalid);
        };
        if !tx.witness_set.is_valid_for(&tx.message) {
            return Err(Error::Invalid);
        }
        let signers = tx.witness_set.signatures_and_public_keys();
        if !(1..=2).contains(&signers.len()) || signers.len() != tx.message.nonces.len() {
            return Err(Error::Invalid);
        }
        let mut seen = BTreeSet::new();
        for (_, public_key) in signers {
            let id = lee::AccountId::from(public_key);
            if !accounts.contains(id.value())
                || private.contains(id.value())
                || !tx.message.account_ids.contains(&id)
                || !seen.insert(*id.value())
            {
                return Err(Error::Invalid);
            }
        }
    }
    Ok(())
}
impl Keyring {
    /// Trusted executor only. This must succeed before any broadcast attempt.
    pub fn retain_public_submission(
        &mut self,
        id: &str,
        principal: &Principal,
        endpoint: &str,
        transaction: LeeTransaction,
    ) -> Result<HashType> {
        let hash = transaction.hash();
        let mut book = self.book.clone();
        book.public_submissions.push(Submission {
            id: id.into(),
            principal: principal.clone(),
            endpoint: endpoint.into(),
            transaction,
            state: SubmissionState::PreparedOrSubmissionUnknown,
            last_checked_at: None,
        });
        self.commit(book)?;
        Ok(hash)
    }
    /// RPC acknowledgement only; this never labels a transaction included/final.
    pub fn mark_public_submission(&mut self, id: &str, submitted: bool) -> Result<()> {
        let mut book = self.book.clone();
        let record = book
            .public_submissions
            .iter_mut()
            .find(|record| record.id == id)
            .ok_or(Error::NotFound)?;
        record.state = if submitted {
            SubmissionState::Submitted
        } else {
            SubmissionState::Uncertain
        };
        self.commit(book)
    }
    /// Recheck the exact saved hash at its original, currently selected node.
    /// The SDK validates the returned transaction's hash and signatures. This
    /// records only the sequencer's inclusion claim at `now`, not finality.
    /// Missing transactions remain uncertain; this never broadcasts anything.
    pub fn reconcile_public_submission(
        &mut self,
        principal: &Principal,
        id: &str,
        selected_endpoint: &str,
        now: u64,
    ) -> Result<SubmissionStatus> {
        self.ensure_current()?;
        let record = self
            .book
            .public_submissions
            .iter()
            .find(|record| &record.principal == principal && record.id == id)
            .ok_or(Error::NotFound)?;
        if record.endpoint != selected_endpoint {
            return Err(Error::SubmissionNetwork);
        }
        let node = logos_registry_sdk::HttpNode::new(&record.endpoint)?;
        let included = node
            .confirmed_transaction(record.transaction.hash())?
            .is_some();
        let mut book = self.book.clone();
        let saved = book
            .public_submissions
            .iter_mut()
            .find(|record| record.id == id)
            .ok_or(Error::NotFound)?;
        saved.state = if included {
            SubmissionState::IncludedBySequencer
        } else {
            SubmissionState::Uncertain
        };
        saved.last_checked_at = Some(now);
        let status = saved.status();
        self.commit(book)?;
        Ok(status)
    }
    /// Trusted owner channel only: resolve the original principal internally.
    /// The public dispatcher must continue using principal-scoped reconciliation.
    pub(crate) fn reconcile_owner_public_submission(
        &mut self,
        id: &str,
        endpoint: &str,
        now: u64,
    ) -> Result<SubmissionStatus> {
        self.ensure_current()?;
        let principal = self
            .book
            .public_submissions
            .iter()
            .find(|record| record.id == id)
            .ok_or(Error::NotFound)?
            .principal
            .clone();
        self.reconcile_public_submission(&principal, id, endpoint, now)
    }
    /// Each app can inspect only its own approved submission metadata.
    pub fn public_submission(&self, principal: &Principal, id: &str) -> Result<SubmissionStatus> {
        self.ensure_current()?;
        self.book
            .public_submissions
            .iter()
            .find(|record| &record.principal == principal && record.id == id)
            .map(Submission::status)
            .ok_or(Error::NotFound)
    }
    /// Trusted wallet UI only; do not expose all applications' history over IPC.
    pub fn public_outbox(&self) -> Vec<SubmissionStatus> {
        self.book
            .public_submissions
            .iter()
            .map(Submission::status)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, Read, Write},
        net::TcpListener,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    #[test]
    fn outbox_rejects_missing_duplicate_foreign_and_private_signers() {
        let keys = [
            lee::PrivateKey::try_new([1; 32]).unwrap(),
            lee::PrivateKey::try_new([2; 32]).unwrap(),
            lee::PrivateKey::try_new([3; 32]).unwrap(),
        ];
        let ids = keys
            .iter()
            .map(|key| lee::AccountId::from(&lee::PublicKey::new_from_private_key(key)))
            .collect::<Vec<_>>();
        let accounts = BTreeSet::from([*ids[0].value(), *ids[1].value()]);
        let record = |signers: &[&lee::PrivateKey]| {
            let message = lee::public_transaction::Message::try_new(
                programs::token().id(),
                ids.clone(),
                vec![lee_core::account::Nonce(0); 2],
                token_core::Instruction::Transfer {
                    amount_to_transfer: 4,
                },
            )
            .unwrap();
            let witness = lee::public_transaction::WitnessSet::for_message(&message, signers);
            Submission {
                id: "a".repeat(32),
                principal: Principal::Module {
                    name: "fixture".into(),
                    instance: String::new(),
                },
                endpoint: "http://fixture.invalid".into(),
                transaction: LeeTransaction::Public(lee::PublicTransaction::new(message, witness)),
                state: SubmissionState::PreparedOrSubmissionUnknown,
                last_checked_at: None,
            }
        };
        assert!(
            validate(
                &[record(&[&keys[0], &keys[1]])],
                &accounts,
                &BTreeSet::new()
            )
            .is_ok()
        );
        for signers in [
            vec![],
            vec![&keys[0]],
            vec![&keys[0], &keys[0]],
            vec![&keys[0], &keys[2]],
            vec![&keys[0], &keys[1], &keys[2]],
        ] {
            assert!(validate(&[record(&signers)], &accounts, &BTreeSet::new()).is_err());
        }
        assert!(
            validate(
                &[record(&[&keys[0], &keys[1]])],
                &accounts,
                &BTreeSet::from([*ids[1].value()])
            )
            .is_err()
        );
    }
    #[test]
    fn reconciliation_rejects_wrong_identity_network_and_hash_and_tracks_disappearance() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("outbox.sqlite");
        let mut ring = Keyring::create(&path, b"outbox check fixture").unwrap();
        let account = ring.import_public("Fixture", &[1; 32]).unwrap();
        let key = lee::PrivateKey::try_new([1; 32]).unwrap();
        let transaction = |amount| {
            let message = lee::public_transaction::Message::try_new(
                programs::authenticated_transfer().id(),
                vec![account, lee::AccountId::new([2; 32])],
                vec![lee_core::account::Nonce(0)],
                authenticated_transfer_core::Instruction::Transfer { amount },
            )
            .unwrap();
            let witness = lee::public_transaction::WitnessSet::for_message(&message, &[&key]);
            LeeTransaction::Public(lee::PublicTransaction::new(message, witness))
        };
        let expected = transaction(1);
        let wrong = transaction(2);
        let hash = expected.hash();
        let saved_transaction = expected.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let called = calls.clone();
        let worker = std::thread::spawn(move || {
            for result in [
                serde_json::Value::Null,
                serde_json::json!([wrong, {}]),
                serde_json::json!([expected, {}]),
                serde_json::Value::Null,
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut length = None;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = Some(value.trim().parse::<usize>().unwrap());
                    }
                }
                let mut body = vec![0; length.unwrap()];
                reader.read_exact(&mut body).unwrap();
                let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(request["method"], "getTransaction");
                assert_eq!(request["params"], serde_json::json!([hash]));
                called.fetch_add(1, Ordering::SeqCst);
                let response =
                    serde_json::json!({"jsonrpc":"2.0","id":request["id"],"result":result})
                        .to_string();
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",response.len(),response).unwrap();
            }
        });
        let app = Principal::Module {
            name: "app".into(),
            instance: String::new(),
        };
        let other = Principal::Module {
            name: "other".into(),
            instance: String::new(),
        };
        let id = "11".repeat(16);
        ring.retain_public_submission(&id, &app, &endpoint, saved_transaction)
            .unwrap();
        assert!(
            ring.reconcile_public_submission(&other, &id, &endpoint, 10)
                .is_err()
        );
        assert!(matches!(
            ring.reconcile_public_submission(&app, &id, "http://127.0.0.1:1", 10),
            Err(Error::SubmissionNetwork)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let missing = ring
            .reconcile_public_submission(&app, &id, &endpoint, 11)
            .unwrap();
        assert_eq!(missing.state, SubmissionState::Uncertain);
        assert_eq!(missing.last_checked_at, Some(11));
        assert!(
            ring.reconcile_public_submission(&app, &id, &endpoint, 12)
                .is_err()
        );
        assert_eq!(
            ring.public_submission(&app, &id).unwrap().last_checked_at,
            Some(11)
        );
        let included = ring
            .reconcile_public_submission(&app, &id, &endpoint, 13)
            .unwrap();
        assert_eq!(included.state, SubmissionState::IncludedBySequencer);
        assert_eq!(included.last_checked_at, Some(13));
        let missing_again = ring
            .reconcile_public_submission(&app, &id, &endpoint, 14)
            .unwrap();
        assert_eq!(missing_again.state, SubmissionState::Uncertain);
        assert_eq!(missing_again.hash, hash);
        worker.join().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        drop(ring);
        let restored = Keyring::open(&path, b"outbox check fixture").unwrap();
        assert_eq!(
            restored
                .public_submission(&app, &id)
                .unwrap()
                .last_checked_at,
            Some(14)
        );
    }
}
