// SPDX-License-Identifier: MIT OR Apache-2.0
use logos_lez_v03::{AccountId, NATIVE_PROGRAM, Node, ShardSelector, UPSTREAM_REVISION};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err("Usage: lez-v03-inspect RPC PUBLIC_BASE58_ACCOUNT (read-only)".into());
    }
    let account: AccountId = args[2].parse()?;
    let node = Node::new(&args[1])?;
    let programs = node.program_ids()?;
    let quote = node.fee_quote()?;
    let view = node.account_view(&ShardSelector {
        account_id: account,
        program_account_id: NATIVE_PROGRAM,
    })?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "endpoint":args[1], "wire_contract_revision":UPSTREAM_REVISION,
            "account":account,"nonce":view.nonce.to_string(),"native_balance":view.native_balance()?.to_string(),
            "program_ids":programs,"fee_quote":quote,
            "scope":"Read-only v0.3 node observations. No signing, funds requested, transaction submission, or independent chain verification."
        }))?
    );
    Ok(())
}
