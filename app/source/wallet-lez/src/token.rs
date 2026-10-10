// SPDX-License-Identifier: MIT OR Apache-2.0
//! Public token holding initialization and transfers using pinned token-program types.
use crate::{Error, NativeWallet, Node, PreparedTransfer, Result};
use lee::{AccountId, public_transaction::Message};
use logos_wallet_policy::{AppId, Effect, Policy, Scope};
use token_core::{TokenDefinition, TokenHolding};

/// Lossless JSON projection for native UI/SDK consumers with limited integer precision.
#[derive(serde::Serialize)]
pub enum HoldingView {
    Fungible {
        definition_id: AccountId,
        balance: String,
    },
    NftMaster {
        definition_id: AccountId,
        print_balance: String,
    },
    NftPrintedCopy {
        definition_id: AccountId,
        owned: bool,
    },
}
impl From<TokenHolding> for HoldingView {
    fn from(holding: TokenHolding) -> Self {
        match holding {
            TokenHolding::Fungible {
                definition_id,
                balance,
            } => Self::Fungible {
                definition_id,
                balance: balance.to_string(),
            },
            TokenHolding::NftMaster {
                definition_id,
                print_balance,
            } => Self::NftMaster {
                definition_id,
                print_balance: print_balance.to_string(),
            },
            TokenHolding::NftPrintedCopy {
                definition_id,
                owned,
            } => Self::NftPrintedCopy {
                definition_id,
                owned,
            },
        }
    }
}
pub struct FungibleTransfer {
    pub from: [u8; 32],
    pub to: [u8; 32],
    /// Expected definition, checked against both actual holdings.
    pub asset: [u8; 32],
    pub amount: u128,
}
pub struct NftTransfer {
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub collection: [u8; 32],
}
impl<N: Node> NativeWallet<N> {
    /// Only the new holding signs; the definition is a read-only program input.
    pub fn prepare_token_initialize(
        &self,
        policy: &mut Policy,
        app: &AppId,
        holding: [u8; 32],
        definition: [u8; 32],
        now: u64,
    ) -> Result<PreparedTransfer> {
        if !policy.permitted(app, Scope::Transactions, Some(holding)) {
            return Err(Error::Invalid("Transaction permission denied"));
        }
        if holding == definition {
            return Err(Error::Invalid("Holding and definition must differ"));
        }
        let state = self.node.account(AccountId::new(holding))?;
        if state != lee::Account::default() {
            return Err(Error::Invalid("Token holding must be an unused account"));
        }
        let asset = self.node.account(AccountId::new(definition))?;
        require_token_owner(&asset)?;
        let parsed = TokenDefinition::try_from(&asset.data)
            .map_err(|_| Error::Invalid("Invalid token definition data"))?;
        let kind = match parsed {
            TokenDefinition::Fungible { .. } => "fungible",
            TokenDefinition::NonFungible { .. } => "NFT printed-copy",
        };
        let message = Message::try_new(
            programs::token().id(),
            vec![AccountId::new(definition), AccountId::new(holding)],
            vec![state.nonce],
            token_core::Instruction::InitializeAccount,
        )
        .map_err(|_| Error::Invalid("Unable to encode token holding initialization"))?;
        self.prepare_message(policy, app, holding, message, vec![Effect::ContractCall {
            program: logos_registry_sdk::program_bytes(&programs::token().id()),
            instruction: "InitializeAccount".into(),
            explanation: format!("Initialize an empty {kind} holding for definition {}. This account becomes owned by the token program; no tokens are minted or transferred.", AccountId::new(definition)),
        }], now)
    }
    /// Read one explicitly permitted public holding. Does not discover an owner's accounts.
    pub fn public_nft_holding(
        &self,
        policy: &Policy,
        app: &AppId,
        holding: [u8; 32],
    ) -> Result<TokenHolding> {
        if !policy.permitted(app, Scope::NftEnumeration, Some(holding)) {
            return Err(Error::Invalid("NFT enumeration permission denied"));
        }
        let state = self.node.account(AccountId::new(holding))?;
        require_token_owner(&state)?;
        let value = TokenHolding::try_from(&state.data)
            .map_err(|_| Error::Invalid("Invalid NFT holding data"))?;
        if matches!(value, TokenHolding::Fungible { .. }) {
            return Err(Error::Invalid("Holding is fungible, not an NFT"));
        }
        Ok(value)
    }
    pub fn prepare_nft(
        &self,
        policy: &mut Policy,
        app: &AppId,
        transfer: NftTransfer,
        now: u64,
    ) -> Result<PreparedTransfer> {
        self.prepare_nft_mode(policy, app, transfer, now, false)
    }
    /// Explicitly claims a fresh recipient with both accounts' authorization.
    pub fn prepare_nft_to_new_holding(
        &self,
        policy: &mut Policy,
        app: &AppId,
        transfer: NftTransfer,
        now: u64,
    ) -> Result<PreparedTransfer> {
        self.prepare_nft_mode(policy, app, transfer, now, true)
    }
    fn prepare_nft_mode(
        &self,
        policy: &mut Policy,
        app: &AppId,
        transfer: NftTransfer,
        now: u64,
        claim_recipient: bool,
    ) -> Result<PreparedTransfer> {
        let NftTransfer {
            from,
            to,
            collection,
        } = transfer;
        if !policy.permitted(app, Scope::Transactions, Some(from))
            || (claim_recipient && !policy.permitted(app, Scope::Transactions, Some(to)))
        {
            return Err(Error::Invalid("Transaction permission denied"));
        }
        if from == to {
            return Err(Error::Invalid("NFT recipient must differ from sender"));
        }
        let sender = self.node.account(AccountId::new(from))?;
        let recipient = self.node.account(AccountId::new(to))?;
        require_token_owner(&sender)?;
        let source = TokenHolding::try_from(&sender.data)
            .map_err(|_| Error::Invalid("Invalid sender token holding"))?;
        let target = if claim_recipient {
            if recipient != lee::Account::default() {
                return Err(Error::Invalid(
                    "Claim recipient must be a fresh unused account",
                ));
            }
            TokenHolding::zeroized_clone_from(&source)
        } else {
            require_token_owner(&recipient)?;
            TokenHolding::try_from(&recipient.data)
                .map_err(|_| Error::Invalid("Invalid recipient token holding"))?
        };
        if source.definition_id().value() != &collection
            || target.definition_id().value() != &collection
        {
            return Err(Error::Invalid(
                "NFT collection differs from requested collection",
            ));
        }
        let (amount, explanation) = match (source, target) {
            (TokenHolding::NftPrintedCopy { owned: true, .. }, TokenHolding::NftPrintedCopy { owned: false, .. }) =>
                (1, "Transfer one printed NFT copy. The source holding ID identifies its current location; the reference program provides no stable copy serial.".to_owned()),
            (TokenHolding::NftMaster { print_balance, .. }, TokenHolding::NftMaster { print_balance: 0, .. }) if print_balance > 0 =>
                (print_balance, format!("Transfer the master NFT and all {} remaining print rights. This is not a transfer of one printed copy.", print_balance - 1)),
            _ => return Err(Error::Invalid("NFT is not owned, recipient is occupied, or holding kinds differ")),
        };
        let message = Message::try_new(
            programs::token().id(),
            vec![AccountId::new(from), AccountId::new(to)],
            if claim_recipient {
                vec![sender.nonce, recipient.nonce]
            } else {
                vec![sender.nonce]
            },
            token_core::Instruction::Transfer {
                amount_to_transfer: amount,
            },
        )
        .map_err(|_| Error::Invalid("Unable to encode NFT transfer"))?;
        let mut prepared = self.prepare_message(
            policy,
            app,
            from,
            message,
            vec![
                Effect::NftTransfer {
                    collection,
                    token: from,
                    destination: to,
                },
                Effect::ContractCall {
                    program: logos_registry_sdk::program_bytes(&programs::token().id()),
                    instruction: "Transfer NFT".into(),
                    explanation: if claim_recipient {format!("{explanation} Claim fresh recipient {} for collection {} as the same holding kind. Both source and recipient sign this transaction; the recipient becomes owned by the token program.",AccountId::new(to),AccountId::new(collection))} else {explanation},
                },
            ],
            now,
        )?;
        if claim_recipient {
            prepared.signing_accounts.push(AccountId::new(to));
        }
        Ok(prepared)
    }

    pub fn fungible_balance(
        &self,
        policy: &Policy,
        app: &AppId,
        holding: [u8; 32],
    ) -> Result<([u8; 32], u128)> {
        if !policy.permitted(app, Scope::PublicBalance, Some(holding)) {
            return Err(Error::Invalid("Public balance permission denied"));
        }
        let state = self.node.account(AccountId::new(holding))?;
        decode(&state)
    }
    pub fn prepare_fungible(
        &self,
        policy: &mut Policy,
        app: &AppId,
        transfer: FungibleTransfer,
        now: u64,
    ) -> Result<PreparedTransfer> {
        let FungibleTransfer {
            from,
            to,
            asset,
            amount,
        } = transfer;
        if !policy.permitted(app, Scope::Transactions, Some(from)) {
            return Err(Error::Invalid("Transaction permission denied"));
        }
        if amount == 0 || from == to {
            return Err(Error::Invalid(
                "Transfer needs a positive amount and distinct recipient",
            ));
        }
        let sender = self.node.account(AccountId::new(from))?;
        let recipient = self.node.account(AccountId::new(to))?;
        let (sender_asset, available) = decode(&sender)?;
        let (recipient_asset, destination_balance) = decode(&recipient)?;
        if sender_asset != asset || recipient_asset != asset {
            return Err(Error::Invalid(
                "Token definition differs from requested asset",
            ));
        }
        if available < amount || destination_balance.checked_add(amount).is_none() {
            return Err(Error::Invalid(
                "Insufficient token balance or recipient overflow",
            ));
        }
        let message = Message::try_new(
            programs::token().id(),
            vec![AccountId::new(from), AccountId::new(to)],
            vec![sender.nonce],
            token_core::Instruction::Transfer {
                amount_to_transfer: amount,
            },
        )
        .map_err(|_| Error::Invalid("Unable to encode fungible token transfer"))?;
        self.prepare_message(
            policy,
            app,
            from,
            message,
            vec![Effect::TokenTransfer {
                asset,
                amount: amount.to_string(),
                destination: to,
            }],
            now,
        )
    }
}
fn require_token_owner(account: &lee::Account) -> Result<()> {
    if account.program_owner != programs::token().id() {
        return Err(Error::Invalid(
            "Holding must belong to the pinned token program",
        ));
    }
    Ok(())
}
fn decode(account: &lee::Account) -> Result<([u8; 32], u128)> {
    require_token_owner(account)?;
    match TokenHolding::try_from(&account.data)
        .map_err(|_| Error::Invalid("Invalid token holding data"))?
    {
        TokenHolding::Fungible {
            definition_id,
            balance,
        } => Ok((*definition_id.value(), balance)),
        _ => Err(Error::Invalid(
            "Holding is not fungible; use the NFT transfer flow",
        )),
    }
}

#[cfg(test)]
mod view_tests {
    use super::*;
    #[test]
    fn balances_above_json_number_precision_are_decimal_strings() {
        let view = HoldingView::from(TokenHolding::Fungible {
            definition_id: AccountId::new([1; 32]),
            balance: u128::MAX,
        });
        let json = serde_json::to_value(view).unwrap();
        assert_eq!(json["Fungible"]["balance"], u128::MAX.to_string());
        let view = HoldingView::from(TokenHolding::NftMaster {
            definition_id: AccountId::new([1; 32]),
            print_balance: u128::MAX,
        });
        assert_eq!(
            serde_json::to_value(view).unwrap()["NftMaster"]["print_balance"],
            u128::MAX.to_string()
        );
    }
}
