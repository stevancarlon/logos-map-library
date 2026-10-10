// SPDX-License-Identifier: MIT OR Apache-2.0
use logos_lez_v03::{AccountId, AccountView, MAX_SHARD_BYTES, NATIVE_PROGRAM, Node, ShardSelector};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    thread,
};

fn serve(
    expected_method: &'static str,
    expected_params: Value,
    response: Value,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line.to_lowercase().strip_prefix("content-length:") {
                length = value.trim().parse().unwrap();
            }
        }
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes).unwrap();
        let request: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            request,
            json!({"jsonrpc":"2.0","id":1,"method":expected_method,"params":expected_params})
        );
        let body = serde_json::to_vec(&response).unwrap();
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
        stream.write_all(&body).unwrap();
    });
    (endpoint, handle)
}
fn selector() -> ShardSelector {
    ShardSelector {
        account_id: AccountId::from_bytes([7; 32]),
        program_account_id: NATIVE_PROGRAM,
    }
}
fn envelope(result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":1,"result":result})
}

#[test]
fn exact_native_projection_reads_full_width_balance_and_nonce() {
    let account = json!({"nonce":u128::MAX,"data":{"shards":{NATIVE_PROGRAM.to_string():u128::MAX.to_le_bytes()}}});
    let (endpoint, handle) = serve("getAccountView", json!([selector()]), envelope(account));
    let view = Node::new(&endpoint)
        .unwrap()
        .account_view(&selector())
        .unwrap();
    assert_eq!(view.nonce, u128::MAX);
    assert_eq!(view.native_balance().unwrap(), u128::MAX);
    handle.join().unwrap();
}
#[test]
fn old_schema_and_unsolicited_shards_are_rejected() {
    for account in [
        json!({"nonce":0,"balance":150,"program_owner":vec![0;8],"data":[]}),
        json!({"nonce":0,"data":{"shards":{AccountId::from_bytes([9;32]).to_string():[1]}}}),
        json!({"nonce":0,"data":{"shards":{NATIVE_PROGRAM.to_string():vec![1;MAX_SHARD_BYTES+1]}}}),
    ] {
        let (endpoint, handle) = serve("getAccountView", json!([selector()]), envelope(account));
        assert!(
            Node::new(&endpoint)
                .unwrap()
                .account_view(&selector())
                .is_err()
        );
        handle.join().unwrap();
    }
}
#[test]
fn missing_native_shard_is_zero_but_malformed_encoding_is_not() {
    let view: AccountView =
        serde_json::from_value(json!({"nonce":0,"data":{"shards":{}}})).unwrap();
    assert_eq!(view.native_balance().unwrap(), 0);
    for bytes in [vec![0; 16], vec![1; 15], vec![1; 17]] {
        let view: AccountView = serde_json::from_value(
            json!({"nonce":0,"data":{"shards":{NATIVE_PROGRAM.to_string():bytes}}}),
        )
        .unwrap();
        assert!(view.native_balance().is_err());
    }
}
#[test]
fn rpc_errors_wrong_ids_and_invalid_fee_bands_are_rejected() {
    for response in [
        json!({"jsonrpc":"2.0","id":2,"result":{}}),
        json!({"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"unsupported"}}),
        envelope(
            json!({"height":1,"base_fee_exec":8,"base_fee_stor":8,"next_base_fee_exec_floor":10,"next_base_fee_exec_ceiling":9,"next_base_fee_stor_floor":8,"next_base_fee_stor_ceiling":9,"max_gas_exec":10000000,"max_gas_stor":1000000}),
        ),
    ] {
        let (endpoint, handle) = serve("getFeeState", json!([]), response);
        assert!(Node::new(&endpoint).unwrap().fee_quote().is_err());
        handle.join().unwrap();
    }
}
#[test]
fn valid_fee_quote_preserves_height_and_both_market_bounds() {
    let (endpoint, handle) = serve(
        "getFeeState",
        json!([]),
        envelope(
            json!({"height":123,"base_fee_exec":8,"base_fee_stor":8,"next_base_fee_exec_floor":8,"next_base_fee_exec_ceiling":9,"next_base_fee_stor_floor":8,"next_base_fee_stor_ceiling":9,"max_gas_exec":10000000,"max_gas_stor":1000000}),
        ),
    );
    let quote = Node::new(&endpoint).unwrap().fee_quote().unwrap();
    assert_eq!(
        (
            quote.height,
            quote.next_base_fee_exec_ceiling,
            quote.next_base_fee_stor_floor
        ),
        (123, 9, 8)
    );
    handle.join().unwrap();
}
#[test]
fn addresses_and_endpoints_reject_wrong_domains_of_input() {
    for address in [
        "",
        "Private/11111111111111111111111111111111",
        "0",
        "111111111111111111111111111111111",
    ] {
        assert!(address.parse::<AccountId>().is_err());
    }
    assert_eq!(
        NATIVE_PROGRAM.to_string().parse::<AccountId>().unwrap(),
        NATIVE_PROGRAM
    );
    for endpoint in [
        "file:///tmp/wallet",
        "https://user:password@example.org",
        "https://example.org/?q=1",
        "https://example.org/#frag",
    ] {
        assert!(Node::new(endpoint).is_err());
    }
}
