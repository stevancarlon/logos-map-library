// SPDX-License-Identifier: MIT OR Apache-2.0
//! Explicit public read capabilities. Responses never include private labels,
//! keys, unrelated balances or any claim of private membership proof.
use crate::{
    AccountId, Result, inventory, outbox::Outbox, token::TokenReader, transfer::NativeReader,
};
use logos_wallet_policy::{Scope, principal::Principal};
use serde_json::{Value, json};

impl Outbox {
    pub fn native_balance_for(
        &self,
        caller: &Principal,
        node: &impl NativeReader,
        account: AccountId,
    ) -> Result<Value> {
        self.require_read_scope(caller, account, Scope::PublicBalance)?;
        let view = node.native_view(account)?;
        Ok(
            json!({"protocol":"v0.3","account":account,"native_balance":view.native_balance()?.to_string(),"nonce":view.nonce.to_string(),"privacy":"public","source":"configured_sequencer"}),
        )
    }

    pub fn fungible_balance_for(
        &self,
        caller: &Principal,
        node: &impl TokenReader,
        account: AccountId,
    ) -> Result<Value> {
        self.require_read_scope(caller, account, Scope::PublicBalance)?;
        let value = inventory::read(node, account)?;
        // Never disclose an NFT holding or collection under PublicBalance.
        let token = if value["holding"]["kind"] == "fungible" {
            json!({"balance":value["holding"]["balance"],"collection":value["collection"]})
        } else {
            Value::Null
        };
        Ok(
            json!({"protocol":"v0.3","account":account,"token":token,"privacy":"public","source":"configured_sequencer"}),
        )
    }

    pub fn nft_holdings_for(
        &self,
        caller: &Principal,
        node: &impl TokenReader,
        account: AccountId,
    ) -> Result<Value> {
        self.require_read_scope(caller, account, Scope::NftEnumeration)?;
        let value = inventory::read(node, account)?;
        // One reference-token shard per account, potentially with one owned NFT.
        // A master's print counter counts print rights, not additional owned NFTs.
        let collections = if matches!(
            value["holding"]["kind"].as_str(),
            Some("nft-master" | "nft-copy")
        ) && value["holding"]["owned"] == true
        {
            json!([{"collection":value["collection"],"count":"1","holdings":[{"holding_account":account,"asset":value["holding"],"identifier_note":"Holding address, not a stable token serial."}]}])
        } else {
            json!([])
        };
        Ok(
            json!({"protocol":"v0.3","account":account,"collections":collections,"privacy":"public","source":"configured_sequencer"}),
        )
    }

    /// Public account query; this is deliberately not the private proof API.
    pub fn collection_membership_for(
        &self,
        caller: &Principal,
        node: &impl TokenReader,
        account: AccountId,
        collection: AccountId,
    ) -> Result<Value> {
        let inventory = self.nft_holdings_for(caller, node, account)?;
        let member = inventory["collections"]
            .as_array()
            .expect("constructed array")
            .iter()
            .any(|entry| entry["collection"]["definition"] == collection.to_string());
        Ok(
            json!({"protocol":"v0.3","account":account,"collection":collection,"member":member,"count":if member{"1"}else{"0"},"privacy":"public","source":"configured_sequencer","proof":false}),
        )
    }
}
