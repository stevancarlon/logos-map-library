// SPDX-License-Identifier: MIT OR Apache-2.0
//! Public owner inventory. No automatic media fetching or metadata trust claims.
use crate::{
    AccountId, Error, Result,
    token::{self, TokenDefinition, TokenHolding, TokenReader},
};
use serde_json::{Value, json};
pub fn read(node: &impl TokenReader, account: AccountId) -> Result<Value> {
    let native = node.native_view(account)?;
    let view = node.token_view(account)?;
    if view.nonce != native.nonce {
        return Err(Error::Invalid(
            "account changed while reading inventory; refresh",
        ));
    }
    let holding = token::holding(&view)?;
    let (display, collection) = if let Some(holding) = holding {
        node.verify_token_program()?;
        let (id, display) = match holding {
            TokenHolding::Fungible {
                definition_id,
                balance,
            } => (
                definition_id,
                json!({"kind":"fungible","balance":balance.to_string()}),
            ),
            TokenHolding::NftMaster {
                definition_id,
                print_balance,
            } => (
                definition_id,
                json!({"kind":"nft-master","owned":print_balance>0,"print_counter":print_balance.to_string(),"remaining_print_rights":print_balance.saturating_sub(1).to_string()}),
            ),
            TokenHolding::NftPrintedCopy {
                definition_id,
                owned,
            } => (
                definition_id,
                json!({"kind":"nft-copy","owned":owned,"identifier_note":"Holding address; not a stable printed-copy serial."}),
            ),
        };
        let definition = AccountId::from_bytes(*id.value());
        let descriptor = token::definition(&node.token_view(definition)?)?;
        let (name, metadata) = match descriptor {
            TokenDefinition::Fungible {
                name, metadata_id, ..
            } if display["kind"] == "fungible" => (name, metadata_id),
            TokenDefinition::NonFungible {
                name, metadata_id, ..
            } if display["kind"] != "fungible" => (name, Some(metadata_id)),
            _ => return Err(Error::Invalid("holding and collection kinds differ")),
        };
        let metadata = metadata.map(|id| AccountId::from_bytes(*id.value()));
        (
            display,
            json!({"definition":definition,"name":name,"metadata_account":metadata,"metadata_status":if metadata.is_some(){"not_fetched"}else{"missing"},"reference_program_verified":true}),
        )
    } else {
        (json!({"kind":"empty"}), Value::Null)
    };
    Ok(
        json!({"account":account,"native_balance":native.native_balance()?.to_string(),"nonce":native.nonce.to_string(),"holding":display,"collection":collection,"source":"configured_sequencer","privacy":"public"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccountData, AccountView, FeeQuote, NATIVE_PROGRAM, transfer::NativeReader};
    use std::collections::BTreeMap;
    struct Reader {
        holding: Vec<u8>,
        definition: Vec<u8>,
        nonce: u128,
        verified: bool,
    }
    fn account() -> AccountId {
        AccountId::from_bytes([1; 32])
    }
    fn definition() -> AccountId {
        AccountId::from_bytes([2; 32])
    }
    fn up() -> lee_v03::AccountId {
        lee_v03::AccountId::new(definition().bytes())
    }
    impl NativeReader for Reader {
        fn native_view(&self, _: AccountId) -> Result<AccountView> {
            Ok(AccountView {
                nonce: 0,
                data: AccountData {
                    shards: BTreeMap::from([(NATIVE_PROGRAM, u128::MAX.to_le_bytes().to_vec())]),
                },
            })
        }
        fn fees(&self) -> Result<FeeQuote> {
            Err(Error::Invalid("inventory must not request fees"))
        }
    }
    impl TokenReader for Reader {
        fn token_view(&self, id: AccountId) -> Result<AccountView> {
            Ok(AccountView {
                nonce: self.nonce,
                data: AccountData {
                    shards: BTreeMap::from([(
                        token::program(),
                        if id == definition() {
                            self.definition.clone()
                        } else {
                            self.holding.clone()
                        },
                    )]),
                },
            })
        }
        fn verify_token_program(&self) -> Result<()> {
            if self.verified {
                Ok(())
            } else {
                Err(Error::Invalid("reference image differs"))
            }
        }
    }
    #[test]
    fn inventory_preserves_integer_precision_and_missing_metadata_and_ownership_states() {
        let big = 1u128 << 100;
        let mut node = Reader {
            holding: vec![],
            definition: vec![],
            nonce: 0,
            verified: false,
        };
        let empty = read(&node, account()).unwrap();
        assert_eq!(empty["native_balance"], u128::MAX.to_string());
        assert_eq!(empty["holding"]["kind"], "empty");
        assert!(empty["collection"].is_null());
        node.verified = true;
        node.definition = borsh::to_vec(&TokenDefinition::Fungible {
            name: "Untrusted <b>name</b>".into(),
            total_supply: big,
            metadata_id: None,
        })
        .unwrap();
        node.holding = borsh::to_vec(&TokenHolding::Fungible {
            definition_id: up(),
            balance: big,
        })
        .unwrap();
        let token = read(&node, account()).unwrap();
        assert_eq!(token["holding"]["balance"], big.to_string());
        assert_eq!(token["collection"]["metadata_status"], "missing");
        assert_eq!(token["collection"]["definition"], definition().to_string());
        node.definition = borsh::to_vec(&TokenDefinition::NonFungible {
            name: "NFT fixture".into(),
            printable_supply: 7,
            metadata_id: up(),
        })
        .unwrap();
        node.holding = borsh::to_vec(&TokenHolding::NftMaster {
            definition_id: up(),
            print_balance: 7,
        })
        .unwrap();
        let master = read(&node, account()).unwrap();
        assert_eq!(master["holding"]["remaining_print_rights"], "6");
        assert_eq!(master["collection"]["metadata_status"], "not_fetched");
        node.holding = borsh::to_vec(&TokenHolding::NftPrintedCopy {
            definition_id: up(),
            owned: false,
        })
        .unwrap();
        let copy = read(&node, account()).unwrap();
        assert_eq!(copy["holding"]["owned"], false);
        assert!(
            copy["holding"]["identifier_note"]
                .as_str()
                .unwrap()
                .contains("not a stable")
        );
    }
    #[test]
    fn inventory_rejects_changed_nonce_image_collection_kind_and_malformed_holdings() {
        let mut node = Reader {
            holding: borsh::to_vec(&TokenHolding::NftPrintedCopy {
                definition_id: up(),
                owned: true,
            })
            .unwrap(),
            definition: borsh::to_vec(&TokenDefinition::Fungible {
                name: "Wrong kind".into(),
                total_supply: 1,
                metadata_id: None,
            })
            .unwrap(),
            nonce: 1,
            verified: false,
        };
        assert!(read(&node, account()).is_err());
        node.nonce = 0;
        assert!(read(&node, account()).is_err());
        node.verified = true;
        assert!(read(&node, account()).is_err());
        node.holding.push(0);
        assert!(read(&node, account()).is_err());
    }
}
