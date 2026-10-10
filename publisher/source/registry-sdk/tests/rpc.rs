// SPDX-License-Identifier: MIT OR Apache-2.0
use common::transaction::LeeTransaction;
use logos_registry_sdk::HttpNode;
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};
fn fixture(response: Value) -> (HttpNode, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let node = HttpNode::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let handle = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = vec![];
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            socket.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        let headers = String::from_utf8(request).unwrap();
        let size = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap();
        let mut body = vec![0; size];
        socket.read_exact(&mut body).unwrap();
        let request: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(request["jsonrpc"], "2.0");
        let response = response.to_string();
        write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",response.len(),response).unwrap();
    });
    (node, handle)
}
fn transaction() -> LeeTransaction {
    LeeTransaction::ProgramDeployment(lee::ProgramDeploymentTransaction::new(
        lee::program_deployment_transaction::Message::new(vec![1, 2, 3]),
    ))
}
#[test]
fn submission_requires_the_locally_computed_hash() {
    let tx = transaction();
    let (node, server) = fixture(json!({"jsonrpc":"2.0","id":1,"result":common::HashType([0;32])}));
    assert!(node.submit(&tx).is_err());
    server.join().unwrap();
    let (node, server) = fixture(json!({"jsonrpc":"2.0","id":1,"result":tx.hash()}));
    assert_eq!(node.submit(&tx).unwrap(), tx.hash());
    server.join().unwrap();
}
#[test]
fn absence_is_pending_and_unrelated_confirmation_is_rejected() {
    let tx = transaction();
    let (node, server) = fixture(json!({"jsonrpc":"2.0","id":1,"result":null}));
    assert!(!node.confirmed(tx.hash()).unwrap());
    server.join().unwrap();
    let (node, server) = fixture(json!({"jsonrpc":"2.0","id":1,"result":[tx,1]}));
    assert!(node.confirmed(common::HashType([0; 32])).is_err());
    server.join().unwrap();
}
#[test]
fn wrong_envelope_is_not_confirmation() {
    let (node, server) = fixture(json!({"jsonrpc":"2.0","id":2,"result":null}));
    assert!(node.confirmed(transaction().hash()).is_err());
    server.join().unwrap();
}

#[test]
fn account_balances_and_nonces_preserve_all_128_bits() {
    use logos_registry_sdk::AccountReader;
    let account = lee::Account {
        balance: u128::MAX,
        nonce: lee_core::account::Nonce(u128::MAX),
        ..Default::default()
    };
    let (node, server) = fixture(json!({"jsonrpc":"2.0","id":1,"result":account}));
    let result = node.account(lee::AccountId::new([1; 32])).unwrap();
    assert_eq!(result.balance, u128::MAX);
    assert_eq!(result.nonce.0, u128::MAX);
    server.join().unwrap();
}

#[test]
fn private_membership_checks_shape_position_and_root() {
    let commitment =
        lee_core::Commitment::new(&lee::AccountId::new([8; 32]), &lee::Account::default());
    let proof: lee_core::MembershipProof = (0, vec![]);
    let root = lee_core::compute_digest_for_path(&commitment, &proof);
    let (node, server) = fixture(json!({"jsonrpc":"2.0","id":1,"result":[[proof],root]}));
    assert_eq!(
        node.commitment_membership(commitment).unwrap(),
        (proof.clone(), root)
    );
    server.join().unwrap();
    for result in [
        json!([[proof], vec![0; 32]]),
        json!([[null], root]),
        json!([[], root]),
        json!([[[1, []]], root]),
    ] {
        let (node, server) = fixture(json!({"jsonrpc":"2.0","id":1,"result":result}));
        assert!(node.commitment_membership(commitment).is_err());
        server.join().unwrap();
    }
}

#[test]
fn history_checks_requested_id_and_block_contents() {
    let key = lee::PrivateKey::try_new([9; 32]).unwrap();
    let block = common::block::HashableBlockData {
        block_id: 7,
        prev_block_hash: common::HashType([0; 32]),
        timestamp: 100,
        transactions: vec![],
    }
    .into_pending_block(&key);
    let (node, server) = fixture(json!({"jsonrpc":"2.0","id":1,"result":block}));
    assert_eq!(
        node.block(7).unwrap().unwrap().header.hash,
        block.header.hash
    );
    server.join().unwrap();
    let (node, server) = fixture(json!({"jsonrpc":"2.0","id":1,"result":block}));
    assert!(node.block(8).is_err());
    server.join().unwrap();
    let mut changed = block;
    changed.body.transactions.push(transaction());
    let (node, server) = fixture(json!({"jsonrpc":"2.0","id":1,"result":changed}));
    assert!(node.block(7).is_err());
    server.join().unwrap();
    let (node, server) = fixture(json!({"jsonrpc":"2.0","id":1,"result":null}));
    assert!(node.block(7).unwrap().is_none());
    server.join().unwrap();
}
