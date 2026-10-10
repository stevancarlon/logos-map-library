// SPDX-License-Identifier: MIT OR Apache-2.0
//! Incremental private-account history scans against the configured sequencer.
//! Node inclusion/history is not an independent consensus or finality proof.
use super::{Error, Keyring, Result};
use common::{HashType, transaction::LeeTransaction};
use lee::AccountId;
use lee_core::{Commitment, Nullifier};
use logos_registry_sdk::HttpNode;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Cursor {
    pub(super) endpoint: String,
    pub(super) account: AccountId,
    block: u64,
    hash: HashType,
}
#[derive(Serialize)]
pub struct PrivateSync {
    pub account: AccountId,
    pub through_block: u64,
    pub observed_tip: u64,
    pub caught_up_to_observed_tip: bool,
    pub processed_blocks: u64,
    pub recovered_transactions: Vec<HashType>,
    pub native_base_units: Option<String>,
    pub token_holding: Option<crate::token::HoldingView>,
    pub state_transaction: Option<HashType>,
    pub pending_transaction: Option<HashType>,
}
impl Keyring {
    /// Trusted wallet only. A provider must separately enforce PrivateBalance
    /// permission before disclosing this result to a requesting application.
    /// At most 64 blocks are read per call. Repeat until the observed tip is reached.
    pub fn sync_private(
        &mut self,
        endpoint: &str,
        account: AccountId,
        max_blocks: u64,
    ) -> Result<PrivateSync> {
        if !(1..=64).contains(&max_blocks) {
            return Err(Error::Invalid);
        }
        let (keys, _) = self.private_keys(account)?;
        let node = HttpNode::new(endpoint)?;
        let tip = node.last_block_id()?;
        let mut cursor = self
            .book
            .private_scans
            .iter()
            .find(|c| c.endpoint == endpoint && c.account == account)
            .cloned();
        let record = self
            .book
            .private_initializations
            .iter()
            .find(|r| r.endpoint == endpoint && r.account == account);
        let anchor = record.and_then(|r| {
            if r.included {
                Some(r.transaction.hash())
            } else {
                r.previous.as_ref().map(|p| p.transaction_hash)
            }
        });
        if let Some(hash) = anchor
            && !node.confirmed(hash)?
        {
            return Err(Error::HistoryChanged);
        }
        if let Some(checkpoint) = &cursor {
            if checkpoint.block > tip {
                return Err(Error::HistoryChanged);
            }
            let observed = node.block(checkpoint.block)?;
            let hash = match observed {
                Some(block) => block.header.hash,
                None if checkpoint.block == 0 => HashType([0; 32]),
                None => return Err(Error::HistoryChanged),
            };
            if hash != checkpoint.hash {
                return Err(Error::HistoryChanged);
            }
        } else {
            let genesis = node
                .block(0)?
                .map_or(HashType([0; 32]), |block| block.header.hash);
            cursor = Some(Cursor {
                endpoint: endpoint.into(),
                account,
                block: 0,
                hash: genesis,
            });
        }
        let mut cursor = cursor.ok_or(Error::Invalid)?;
        let start = cursor.block;
        let end = tip.min(start.saturating_add(max_blocks));
        let mut recovered = vec![];
        while cursor.block < end {
            let next = cursor.block.checked_add(1).ok_or(Error::Invalid)?;
            let block = node.block(next)?.ok_or(Error::HistoryChanged)?;
            if block.header.prev_block_hash != cursor.hash {
                return Err(Error::HistoryChanged);
            }
            for transaction in block.body.transactions {
                let LeeTransaction::PrivacyPreserving(private) = &transaction else {
                    continue;
                };
                let record = self
                    .book
                    .private_initializations
                    .iter()
                    .find(|r| r.endpoint == endpoint && r.account == account);
                let before = record.and_then(|r| {
                    if r.included {
                        Some(&r.state)
                    } else {
                        r.previous.as_ref().map(|p| &p.state)
                    }
                });
                let expected = before.map_or_else(
                    || Nullifier::for_account_initialization(&account),
                    |state| {
                        Nullifier::for_account_update(
                            &Commitment::new(&account, state),
                            &keys.nullifier_secret_key,
                        )
                    },
                );
                if private
                    .message
                    .private_actions
                    .iter()
                    .any(|action| action.nullifier == expected)
                {
                    let hash = transaction.hash();
                    // Recovery validates the receipt, exact nullifier, decryption,
                    // nonce and commitment before each atomic state update.
                    if self
                        .recover_private_transaction(endpoint, account, hash)?
                        .is_none()
                    {
                        return Err(Error::HistoryChanged);
                    }
                    recovered.push(hash);
                }
            }
            cursor.block = next;
            cursor.hash = block.header.hash;
        }
        let mut book = self.book.clone();
        if let Some(existing) = book
            .private_scans
            .iter_mut()
            .find(|c| c.endpoint == endpoint && c.account == account)
        {
            *existing = cursor.clone();
        } else {
            book.private_scans.push(cursor.clone());
        }
        self.commit(book)?;
        let record = self
            .book
            .private_initializations
            .iter()
            .find(|r| r.endpoint == endpoint && r.account == account);
        let state = record.and_then(|r| {
            if r.included {
                Some(&r.state)
            } else {
                r.previous.as_ref().map(|p| &p.state)
            }
        });
        let token_holding = state
            .filter(|s| s.program_owner == programs::token().id())
            .map(|s| {
                token_core::TokenHolding::try_from(&s.data)
                    .map(crate::token::HoldingView::from)
                    .map_err(|_| Error::RecoveryMismatch)
            })
            .transpose()?;
        Ok(PrivateSync {
            account,
            through_block: cursor.block,
            observed_tip: tip,
            caught_up_to_observed_tip: cursor.block == tip,
            processed_blocks: cursor.block - start,
            recovered_transactions: recovered,
            native_base_units: state.map(|s| s.balance.to_string()),
            token_holding,
            state_transaction: record.and_then(|r| {
                if r.included {
                    Some(r.transaction.hash())
                } else {
                    r.previous.as_ref().map(|p| p.transaction_hash)
                }
            }),
            pending_transaction: record.filter(|r| !r.included).map(|r| r.transaction.hash()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{
            Arc,
            atomic::{AtomicU8, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };
    #[test]
    fn checkpoint_survives_restart_and_rejects_broken_or_changed_history() {
        // History-only fixture: no synthetic private receipts are accepted here.
        let key = lee::PrivateKey::try_new([9; 32]).unwrap();
        let block1 = common::block::HashableBlockData {
            block_id: 1,
            prev_block_hash: HashType([0; 32]),
            timestamp: 1,
            transactions: vec![],
        }
        .into_pending_block(&key);
        let block2 = common::block::HashableBlockData {
            block_id: 2,
            prev_block_hash: block1.header.hash,
            timestamp: 2,
            transactions: vec![],
        }
        .into_pending_block(&key);
        let broken = common::block::HashableBlockData {
            block_id: 2,
            prev_block_hash: HashType([99; 32]),
            timestamp: 2,
            transactions: vec![],
        }
        .into_pending_block(&key);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let mode = Arc::new(AtomicU8::new(0));
        let server_mode = mode.clone();
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(120);
            while server_mode.load(Ordering::SeqCst) != 255 && Instant::now() < deadline {
                let (mut socket, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("{error}"),
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut header = vec![];
                let mut byte = [0];
                while !header.ends_with(b"\r\n\r\n") {
                    socket.read_exact(&mut byte).unwrap();
                    header.push(byte[0]);
                    assert!(header.len() < 16384);
                }
                let header = String::from_utf8(header).unwrap();
                let length = header
                    .lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                let mut body = vec![0; length];
                socket.read_exact(&mut body).unwrap();
                let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let result = match (
                    request["method"].as_str().unwrap(),
                    request["params"][0].as_u64(),
                ) {
                    ("getLastBlockId", _) => json!(2),
                    ("getBlock", Some(0)) => json!(null),
                    ("getBlock", Some(1)) => json!(block1),
                    ("getBlock", Some(2)) => {
                        if server_mode.load(Ordering::SeqCst) == 0 {
                            json!(block2)
                        } else {
                            json!(broken)
                        }
                    }
                    _ => panic!("Unexpected fixture request"),
                };
                let response = json!({"jsonrpc":"2.0","id":1,"result":result}).to_string();
                write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",response.len(),response).unwrap();
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scan.sqlite");
        let mut ring = Keyring::create(&path, b"history fixture").unwrap();
        let account = ring.generate_private("Scan fixture").unwrap();
        let first = ring.sync_private(&endpoint, account, 1).unwrap();
        assert_eq!(first.through_block, 1);
        assert!(!first.caught_up_to_observed_tip);
        assert!(first.native_base_units.is_none());
        drop(ring);
        let mut ring = Keyring::open(&path, b"history fixture").unwrap();
        mode.store(1, Ordering::SeqCst);
        assert!(matches!(
            ring.sync_private(&endpoint, account, 1),
            Err(Error::HistoryChanged)
        ));
        assert_eq!(ring.book.private_scans[0].block, 1);
        mode.store(0, Ordering::SeqCst);
        let second = ring.sync_private(&endpoint, account, 1).unwrap();
        assert_eq!(second.processed_blocks, 1);
        assert_eq!(second.through_block, 2);
        assert!(second.caught_up_to_observed_tip);
        mode.store(1, Ordering::SeqCst);
        assert!(matches!(
            ring.sync_private(&endpoint, account, 1),
            Err(Error::HistoryChanged)
        ));
        mode.store(255, Ordering::SeqCst);
        server.join().unwrap();
    }
}
