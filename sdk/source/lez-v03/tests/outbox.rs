// SPDX-License-Identifier: MIT OR Apache-2.0
use base64::{Engine, engine::general_purpose::STANDARD};
use lee_core_v03::{
    account::ProgramShardSelector,
    native_token::{Instruction, NATIVE_TOKEN_PROGRAM_ID},
};
use lee_v03::{
    PrivateKey, PublicKey, PublicTransaction,
    fees::FeeDeclaration,
    public_transaction::{Message, WitnessSet},
};
use logos_lez_v03::{
    Error, Node, Result,
    outbox::{Outbox, State, SubmissionNode},
};
use logos_wallet_policy::principal::Principal;
use serde_json::{Value, json};
use std::{
    cell::Cell,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    path::PathBuf,
    thread,
};
const PASSWORD: &[u8] = b"v03 disposable fixture password";
const ID: &str = "0123456789abcdef0123456789abcdef";
fn signed(amount: u128) -> PublicTransaction {
    let key = PrivateKey::try_new([1; 32]).unwrap();
    let from = lee_v03::AccountId::from(&PublicKey::new_from_private_key(&key));
    let to = lee_v03::AccountId::new([7; 32]);
    let message = Message::try_new_with_fees(
        NATIVE_TOKEN_PROGRAM_ID,
        vec![
            ProgramShardSelector::native_balance(from),
            ProgramShardSelector::native_balance(to),
        ],
        vec![0.into()],
        Instruction::Transfer { amount },
        FeeDeclaration::new(from, 1000, 0, 20_000),
    )
    .unwrap();
    let witness = WitnessSet::for_message(&message, &[&key]);
    PublicTransaction::new(message, witness)
}
struct FixtureNode {
    path: PathBuf,
    posts: Cell<usize>,
    reads: Cell<usize>,
    lost: bool,
    crash: bool,
    included: Cell<bool>,
}
impl SubmissionNode for FixtureNode {
    fn endpoint(&self) -> &str {
        "http://127.0.0.1:3040"
    }
    fn broadcast(&self, tx: &PublicTransaction) -> Result<[u8; 32]> {
        self.posts.set(self.posts.get() + 1);
        // A separately opened store must already contain the exact hash.
        let saved = Outbox::open(&self.path, PASSWORD)
            .unwrap()
            .status(&Principal::LocalCli, ID)
            .unwrap();
        assert_eq!(saved.hash, hex::encode(tx.hash()));
        assert_eq!(saved.state, State::PreparedOrSubmissionUnknown);
        assert!(!self.crash, "simulated process boundary after durable save");
        if self.lost {
            Err(Error::Transport("simulated lost reply".into()))
        } else {
            Ok(tx.hash())
        }
    }
    fn observed(&self, _: &PublicTransaction) -> Result<bool> {
        self.reads.set(self.reads.get() + 1);
        Ok(self.included.get())
    }
}
fn fixture_node(path: PathBuf) -> FixtureNode {
    FixtureNode {
        path,
        posts: Cell::new(0),
        reads: Cell::new(0),
        lost: false,
        crash: false,
        included: Cell::new(false),
    }
}
#[test]
fn lost_reply_survives_restart_without_duplicate_and_reconciles_exact_saved_request() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("outbox.sqlite");
    let mut node = fixture_node(path.clone());
    node.lost = true;
    let tx = signed(100);
    let mut outbox = Outbox::create(&path, PASSWORD).unwrap();
    let status = outbox
        .submit_new(&Principal::LocalCli, ID, &node, tx.clone())
        .unwrap();
    assert_eq!(status.state, State::Uncertain);
    drop(outbox);
    assert!(Outbox::open(&path, b"wrong password").is_err());
    let mut outbox = Outbox::open(&path, PASSWORD).unwrap();
    assert_eq!(outbox.status(&Principal::LocalCli, ID).unwrap(), status);
    assert!(
        outbox
            .submit_new(&Principal::LocalCli, ID, &node, tx.clone())
            .is_err()
    );
    assert!(
        outbox
            .submit_new(
                &Principal::LocalCli,
                "1123456789abcdef0123456789abcdef",
                &node,
                tx
            )
            .is_err()
    );
    assert_eq!(node.posts.get(), 1);
    assert_eq!(
        outbox
            .reconcile(&Principal::LocalCli, ID, &node, 123)
            .unwrap()
            .state,
        State::Uncertain
    );
    node.included.set(true);
    let status = outbox
        .reconcile(&Principal::LocalCli, ID, &node, 124)
        .unwrap();
    assert_eq!(status.state, State::IncludedBySequencer);
    assert_eq!(status.last_checked_at, Some(124));
    assert_eq!(node.posts.get(), 1);
    let bytes = std::fs::read(path).unwrap();
    assert!(!bytes.windows(ID.len()).any(|part| part == ID.as_bytes()));
    assert!(
        !bytes
            .windows(status.hash.len())
            .any(|part| part == status.hash.as_bytes())
    );
}
#[test]
fn crash_boundary_keeps_saved_hash_and_caller_network_isolation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("outbox.sqlite");
    let mut node = fixture_node(path.clone());
    node.crash = true;
    let mut outbox = Outbox::create(&path, PASSWORD).unwrap();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| outbox.submit_new(
            &Principal::LocalCli,
            ID,
            &node,
            signed(100)
        )))
        .is_err()
    );
    drop(outbox);
    let mut outbox = Outbox::open(&path, PASSWORD).unwrap();
    assert_eq!(
        outbox.status(&Principal::LocalCli, ID).unwrap().state,
        State::PreparedOrSubmissionUnknown
    );
    let other = Principal::Module {
        name: "other".into(),
        instance: String::new(),
    };
    assert!(outbox.status(&other, ID).is_err());
    assert!(outbox.reconcile(&other, ID, &node, 1).is_err());
    assert_eq!(node.reads.get(), 0);
    let wrong_endpoint = Node::new("http://127.0.0.1:1").unwrap();
    assert!(
        outbox
            .reconcile(&Principal::LocalCli, ID, &wrong_endpoint, 1)
            .is_err()
    );
    assert_eq!(
        outbox
            .reconcile(&Principal::LocalCli, ID, &node, 2)
            .unwrap()
            .state,
        State::Uncertain
    );
    assert_eq!(node.posts.get(), 1);
}
#[test]
fn stale_writer_and_legacy_payload_cannot_replace_v03_outbox() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("outbox.sqlite");
    let node = fixture_node(path.clone());
    let mut first = Outbox::create(&path, PASSWORD).unwrap();
    let mut stale = Outbox::open(&path, PASSWORD).unwrap();
    assert_eq!(
        first
            .submit_new(&Principal::LocalCli, ID, &node, signed(100))
            .unwrap()
            .state,
        State::Submitted
    );
    assert!(
        stale
            .submit_new(
                &Principal::LocalCli,
                "1123456789abcdef0123456789abcdef",
                &node,
                signed(101)
            )
            .is_err()
    );
    assert_eq!(node.posts.get(), 1);
    assert!(Outbox::create(&path, PASSWORD).is_err());
    let legacy = dir.path().join("legacy.sqlite");
    logos_wallet_store::Store::create(&legacy, PASSWORD, br#"{"format":"legacy","records":[]}"#)
        .unwrap();
    assert!(Outbox::open(&legacy, PASSWORD).is_err());
}
fn rpc(expected: Value, response: Value) -> (Node, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let node = Node::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut len = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some(v) = line.to_lowercase().strip_prefix("content-length:") {
                len = v.trim().parse().unwrap();
            }
        }
        let mut bytes = vec![0; len];
        reader.read_exact(&mut bytes).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), expected);
        let body = serde_json::to_vec(&response).unwrap();
        write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
        stream.write_all(&body).unwrap();
    });
    (node, handle)
}
fn wire(tx: &PublicTransaction) -> String {
    let mut bytes = vec![0];
    bytes.extend(borsh::to_vec(tx).unwrap());
    STANDARD.encode(bytes)
}
#[test]
fn rpc_submission_uses_v03_borsh_base64_and_rejects_wrong_acknowledgement() {
    let tx = signed(100);
    let request = json!({"jsonrpc":"2.0","id":1,"method":"sendTransaction","params":[wire(&tx)]});
    for good in [true, false] {
        let result = if good {
            hex::encode(tx.hash())
        } else {
            "00".repeat(32)
        };
        let (node, handle) = rpc(
            request.clone(),
            json!({"jsonrpc":"2.0","id":1,"result":result}),
        );
        assert_eq!(node.broadcast(&tx).is_ok(), good);
        handle.join().unwrap();
    }
}
#[test]
fn confirmation_requires_exact_saved_signed_transaction() {
    let tx = signed(100);
    let request =
        json!({"jsonrpc":"2.0","id":1,"method":"getTransaction","params":[hex::encode(tx.hash())]});
    for (result, expected) in [
        (json!([wire(&tx), 42]), Some(true)),
        (Value::Null, Some(false)),
        (json!([wire(&signed(101)), 42]), None),
        (json!(["not base64", 42]), None),
    ] {
        let (node, handle) = rpc(
            request.clone(),
            json!({"jsonrpc":"2.0","id":1,"result":result}),
        );
        assert_eq!(node.observed(&tx).ok(), expected);
        handle.join().unwrap();
    }
}
