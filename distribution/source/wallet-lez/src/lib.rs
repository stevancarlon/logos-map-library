// SPDX-License-Identifier: MIT OR Apache-2.0
//! Trusted wallet executor for public native transfers. No dApp identity discovery.
//! IPC must authenticate AppId; policy grants/decisions must remain on the wallet UI channel.
pub mod keyring;
mod private_output;
pub mod private_transfer;
pub mod provider;
pub mod shielded;
pub mod shielded_transfer;
pub mod testimonial;
pub mod token;
use common::{HashType, transaction::LeeTransaction};
use lee::{
    AccountId, PrivateKey, PublicKey, PublicTransaction,
    public_transaction::{Message, WitnessSet},
};
use logos_registry_sdk::{AccountReader, HttpNode};
use logos_wallet_policy::{AppId, Effect, Policy, Prompt, Request, Scope, Transaction};
use sha2::{Digest, Sha256};
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Node(#[from] logos_registry_sdk::Error),
    #[error(transparent)]
    Policy(#[from] logos_wallet_policy::Error),
    #[error("{0}")]
    Invalid(&'static str),
    #[error(
        "Submission outcome uncertain for {hash}: {source}. Check transaction status before requesting a new approval."
    )]
    Submission {
        hash: HashType,
        source: logos_registry_sdk::Error,
    },
}
pub type Result<T> = std::result::Result<T, Error>;
/// These fields are private so a dApp cannot rewrite an approved message.
pub struct PreparedTransfer {
    message: Message,
    prompt: Prompt,
    signing_accounts: Vec<AccountId>,
}
impl PreparedTransfer {
    pub fn prompt(&self) -> &Prompt {
        &self.prompt
    }
    pub fn signing_accounts(&self) -> &[AccountId] {
        &self.signing_accounts
    }
}
pub trait Node: AccountReader {
    fn submit_transaction(&self, tx: &LeeTransaction) -> logos_registry_sdk::Result<HashType>;
}
impl Node for HttpNode {
    fn submit_transaction(&self, tx: &LeeTransaction) -> logos_registry_sdk::Result<HashType> {
        self.submit(tx)
    }
}
pub struct NativeWallet<N> {
    node: N,
    endpoint: String,
}
impl NativeWallet<HttpNode> {
    pub fn connect(endpoint: &str) -> Result<Self> {
        Ok(Self {
            node: HttpNode::new(endpoint)?,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
        })
    }
}
impl<N: Node> NativeWallet<N> {
    pub fn public_balance(&self, policy: &Policy, app: &AppId, account: [u8; 32]) -> Result<u128> {
        if !policy.permitted(app, Scope::PublicBalance, Some(account)) {
            return Err(Error::Invalid("Public balance permission denied"));
        }
        Ok(self.node.account(AccountId::new(account))?.balance)
    }
    /// The wallet builds effects from canonical native-transfer inputs, not dApp labels.
    /// Amount uses integer base units. No gas estimate is claimed by this adapter.
    pub fn prepare_native(
        &self,
        policy: &mut Policy,
        app: &AppId,
        transfer: NativeTransfer,
        now: u64,
    ) -> Result<PreparedTransfer> {
        let NativeTransfer { from, to, amount } = transfer;
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
        if sender.program_owner != programs::authenticated_transfer().id() {
            return Err(Error::Invalid(
                "Native sender must use the authenticated transfer program",
            ));
        }
        if sender.balance < amount {
            return Err(Error::Invalid("Insufficient native balance"));
        }
        if recipient.program_owner == lee_core::program::DEFAULT_PROGRAM_ID {
            return Err(Error::Invalid(
                "Recipient account must be initialized before transfer",
            ));
        }
        recipient
            .balance
            .checked_add(amount)
            .ok_or(Error::Invalid("Recipient balance overflow"))?;
        let message = Message::try_new(
            programs::authenticated_transfer().id(),
            vec![AccountId::new(from), AccountId::new(to)],
            vec![sender.nonce],
            authenticated_transfer_core::Instruction::Transfer { amount },
        )
        .map_err(|_| Error::Invalid("Unable to encode native transfer"))?;
        self.prepare_message(
            policy,
            app,
            from,
            message,
            vec![Effect::NativeTransfer {
                amount: amount.to_string(),
                destination: to,
            }],
            now,
        )
    }
    fn prepare_message(
        &self,
        policy: &mut Policy,
        app: &AppId,
        from: [u8; 32],
        message: Message,
        effects: Vec<Effect>,
        now: u64,
    ) -> Result<PreparedTransfer> {
        // LEZ's signed message has no chain ID. Bind the approval to the configured
        // endpoint here; this is wallet-side binding, not chain-level replay protection.
        let mut hash = Sha256::new();
        hash.update(b"logos-wallet-native-approval-v1\0");
        hash.update((self.endpoint.len() as u64).to_le_bytes());
        hash.update(self.endpoint.as_bytes());
        hash.update(message.hash());
        let prompt = policy.request(
            app,
            Request::Transaction(Transaction {
                account: from,
                message_hash: hash.finalize().into(),
                effects,
                network: self.endpoint.clone(),
            }),
            now,
        )?;
        Ok(PreparedTransfer {
            message,
            prompt,
            signing_accounts: vec![AccountId::new(from)],
        })
    }
    pub fn vault_balance(&self, policy: &Policy, app: &AppId, account: [u8; 32]) -> Result<u128> {
        if !policy.permitted(app, Scope::PublicBalance, Some(account)) {
            return Err(Error::Invalid("Public balance permission denied"));
        }
        let vault =
            vault_core::compute_vault_account_id(programs::vault().id(), AccountId::new(account));
        Ok(self.node.account(vault)?.balance)
    }
    /// Initialize a fresh public account before receiving/spending or using registries.
    pub fn prepare_initialize(
        &self,
        policy: &mut Policy,
        app: &AppId,
        account: [u8; 32],
        now: u64,
    ) -> Result<PreparedTransfer> {
        if !policy.permitted(app, Scope::Transactions, Some(account)) {
            return Err(Error::Invalid("Transaction permission denied"));
        }
        let state = self.node.account(AccountId::new(account))?;
        if state != lee::Account::default() {
            return Err(Error::Invalid(
                "Account is already initialized or has state",
            ));
        }
        let program = programs::authenticated_transfer().id();
        let message = Message::try_new(
            program,
            vec![AccountId::new(account)],
            vec![state.nonce],
            authenticated_transfer_core::Instruction::Initialize,
        )
        .map_err(|_| Error::Invalid("Unable to encode initialization"))?;
        self.prepare_message(
            policy,
            app,
            account,
            message,
            vec![Effect::InitializeNativeAccount {
                program: logos_registry_sdk::program_bytes(&program),
            }],
            now,
        )
    }
    /// Claims a chosen amount from the selected account's own on-chain vault.
    pub fn prepare_claim(
        &self,
        policy: &mut Policy,
        app: &AppId,
        account: [u8; 32],
        amount: u128,
        now: u64,
    ) -> Result<PreparedTransfer> {
        if !policy.permitted(app, Scope::Transactions, Some(account)) {
            return Err(Error::Invalid("Transaction permission denied"));
        }
        let owner = AccountId::new(account);
        let state = self.node.account(owner)?;
        let program = programs::vault().id();
        let vault = vault_core::compute_vault_account_id(program, owner);
        let source = self.node.account(vault)?;
        if amount == 0
            || amount > source.balance
            || state.balance.checked_add(amount).is_none()
            || state.program_owner != programs::authenticated_transfer().id()
            || source.program_owner != programs::authenticated_transfer().id()
        {
            return Err(Error::Invalid(
                "Invalid amount, balance, or native account ownership for vault claim",
            ));
        }
        let message = Message::try_new(
            program,
            vec![owner, vault],
            vec![state.nonce],
            vault_core::Instruction::Claim { amount },
        )
        .map_err(|_| Error::Invalid("Unable to encode vault claim"))?;
        self.prepare_message(
            policy,
            app,
            account,
            message,
            vec![Effect::NativeVaultClaim {
                amount: amount.to_string(),
                vault: *vault.value(),
            }],
            now,
        )
    }
    /// Consumes one explicit approval before signing. Does not rebuild a newer nonce.
    /// Returns a signed transaction for durable storage before broadcasting.
    pub fn sign_approved(
        &self,
        policy: &mut Policy,
        app: &AppId,
        prepared: &PreparedTransfer,
        key: &PrivateKey,
        now: u64,
    ) -> Result<LeeTransaction> {
        self.sign_approved_with_keys(policy, app, prepared, &[key], now)
    }
    /// Every signer is fixed by preparation and independently permission checked.
    /// A fresh NFT holding claim requires the recipient's signature as well.
    pub fn sign_approved_with_keys(
        &self,
        policy: &mut Policy,
        app: &AppId,
        prepared: &PreparedTransfer,
        keys: &[&PrivateKey],
        now: u64,
    ) -> Result<LeeTransaction> {
        let Request::Transaction(transaction) = &prepared.prompt.request else {
            return Err(Error::Invalid("Expected transaction approval"));
        };
        if transaction.network != self.endpoint {
            return Err(Error::Invalid("Approved node differs from execution node"));
        }
        if prepared.signing_accounts.first().map(AccountId::value) != Some(&transaction.account)
            || keys.len() != prepared.signing_accounts.len()
            || keys.len() != prepared.message.nonces.len()
            || keys.is_empty()
        {
            return Err(Error::Invalid("Signing account differs from approval"));
        }
        for (key, account) in keys.iter().zip(&prepared.signing_accounts) {
            if AccountId::from(&PublicKey::new_from_private_key(key)) != *account
                || !policy.permitted(app, Scope::Transactions, Some(*account.value()))
            {
                return Err(Error::Invalid(
                    "Every signing account requires transaction permission and its matching key",
                ));
            }
        }
        policy.consume(app, prepared.prompt.id, &prepared.prompt.request, now)?;
        let witness = WitnessSet::for_message(&prepared.message, keys);
        if !witness.is_valid_for(&prepared.message) {
            return Err(Error::Invalid("Invalid native-transfer signature"));
        }
        Ok(LeeTransaction::Public(PublicTransaction::new(
            prepared.message.clone(),
            witness,
        )))
    }
    /// CLI convenience; providers use sign_approved and persist before broadcast.
    /// A matching hash is an RPC acknowledgement, not inclusion or finality.
    pub fn execute(
        &self,
        policy: &mut Policy,
        app: &AppId,
        prepared: &PreparedTransfer,
        key: &PrivateKey,
        now: u64,
    ) -> Result<HashType> {
        let signed = self.sign_approved(policy, app, prepared, key, now)?;
        let hash = signed.hash();
        let returned = self
            .node
            .submit_transaction(&signed)
            .map_err(|source| Error::Submission { hash, source })?;
        if returned != hash {
            return Err(Error::Submission {
                hash,
                source: logos_registry_sdk::Error::Invalid(
                    "Node returned a different transaction hash".into(),
                ),
            });
        }
        Ok(hash)
    }
}
pub struct NativeTransfer {
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub amount: u128,
}
#[cfg(test)]
mod tests {
    use super::*;
    use logos_wallet_policy::Grant;
    use std::{
        cell::RefCell,
        collections::{BTreeMap, BTreeSet},
    };
    struct Memory {
        accounts: BTreeMap<AccountId, lee::Account>,
        sent: RefCell<Vec<LeeTransaction>>,
        lose_response: bool,
    }
    impl AccountReader for Memory {
        fn account(&self, id: AccountId) -> logos_registry_sdk::Result<lee::Account> {
            self.accounts
                .get(&id)
                .cloned()
                .ok_or(logos_registry_sdk::Error::Invalid("Missing fixture".into()))
        }
    }
    impl Node for Memory {
        fn submit_transaction(&self, tx: &LeeTransaction) -> logos_registry_sdk::Result<HashType> {
            self.sent.borrow_mut().push(tx.clone());
            if self.lose_response {
                return Err(logos_registry_sdk::Error::Transport(
                    "Fixture response lost after accepting transaction".into(),
                ));
            }
            Ok(tx.hash())
        }
    }
    fn fixture() -> (NativeWallet<Memory>, Policy, AppId, PrivateKey, [u8; 32]) {
        let key = PrivateKey::try_new([1; 32]).unwrap();
        let from = *AccountId::from(&PublicKey::new_from_private_key(&key)).value();
        let node = Memory {
            accounts: BTreeMap::from([
                (
                    AccountId::new(from),
                    lee::Account {
                        balance: 100,
                        program_owner: programs::authenticated_transfer().id(),
                        ..Default::default()
                    },
                ),
                (
                    AccountId::new([2; 32]),
                    lee::Account {
                        program_owner: programs::authenticated_transfer().id(),
                        ..Default::default()
                    },
                ),
            ]),
            sent: RefCell::new(vec![]),
            lose_response: false,
        };
        let app = AppId("authenticated.test.fixture".into());
        let mut policy = Policy::default();
        policy
            .set_grant(
                app.clone(),
                Grant {
                    accounts: BTreeSet::from([from]),
                    scopes: BTreeSet::from([Scope::Transactions]),
                },
            )
            .unwrap();
        (
            NativeWallet {
                node,
                endpoint: "http://127.0.0.1:1".into(),
            },
            policy,
            app,
            key,
            from,
        )
    }
    #[test]
    fn fresh_master_recipient_requires_both_permissions_keys_and_one_approval() {
        let (mut wallet, mut policy, app, key, from) = fixture();
        let recipient_key = PrivateKey::try_new([2; 32]).unwrap();
        let to = AccountId::from(&PublicKey::new_from_private_key(&recipient_key));
        let collection = AccountId::new([8; 32]);
        wallet.node.accounts.insert(
            AccountId::new(from),
            lee::Account {
                program_owner: programs::token().id(),
                data: (&token_core::TokenHolding::NftMaster {
                    definition_id: collection,
                    print_balance: 4,
                })
                    .into(),
                ..Default::default()
            },
        );
        wallet.node.accounts.insert(to, lee::Account::default());
        let transfer = || token::NftTransfer {
            from,
            to: *to.value(),
            collection: *collection.value(),
        };
        assert!(
            wallet
                .prepare_nft_to_new_holding(&mut policy, &app, transfer(), 100)
                .is_err()
        );
        let grant = Grant {
            accounts: [from, *to.value()].into_iter().collect(),
            scopes: [Scope::Transactions].into_iter().collect(),
        };
        policy.set_grant(app.clone(), grant.clone()).unwrap();
        let prepared = wallet
            .prepare_nft_to_new_holding(&mut policy, &app, transfer(), 100)
            .unwrap();
        assert_eq!(prepared.signing_accounts(), &[AccountId::new(from), to]);
        let Request::Transaction(review) = &prepared.prompt().request else {
            panic!()
        };
        assert!(review.effects.iter().any(|effect| matches!(effect,Effect::ContractCall{explanation,..} if explanation.contains("3 remaining print rights") && explanation.contains("Both source and recipient sign") && explanation.contains(&to.to_string()))));
        assert!(
            wallet
                .sign_approved_with_keys(&mut policy, &app, &prepared, &[&key, &recipient_key], 100)
                .is_err()
        );
        policy.decide(prepared.prompt().id, true, 101).unwrap();
        assert!(
            wallet
                .sign_approved(&mut policy, &app, &prepared, &key, 102)
                .is_err()
        );
        assert!(
            wallet
                .sign_approved_with_keys(&mut policy, &app, &prepared, &[&recipient_key, &key], 102)
                .is_err()
        );
        policy.revoke_account(&app, *to.value());
        assert!(
            wallet
                .sign_approved_with_keys(&mut policy, &app, &prepared, &[&key, &recipient_key], 102)
                .is_err()
        );
        policy.set_grant(app.clone(), grant).unwrap();
        let prepared = wallet
            .prepare_nft_to_new_holding(&mut policy, &app, transfer(), 103)
            .unwrap();
        policy.decide(prepared.prompt().id, true, 104).unwrap();
        let LeeTransaction::Public(signed) = wallet
            .sign_approved_with_keys(&mut policy, &app, &prepared, &[&key, &recipient_key], 105)
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(signed.witness_set.signatures_and_public_keys().len(), 2);
        assert!(signed.witness_set.is_valid_for(&signed.message));
        assert!(
            wallet
                .sign_approved_with_keys(&mut policy, &app, &prepared, &[&key, &recipient_key], 105)
                .is_err()
        );
        wallet.node.accounts.get_mut(&to).unwrap().balance = 1;
        assert!(
            wallet
                .prepare_nft_to_new_holding(&mut policy, &app, transfer(), 106)
                .is_err()
        );
    }
    #[test]
    fn nft_transfers_validate_ownership_kind_collection_and_master_rights() {
        let (mut wallet, mut policy, app, key, from) = fixture();
        let collection = AccountId::new([8; 32]);
        let set = |wallet: &mut NativeWallet<Memory>, id, holding: token_core::TokenHolding| {
            let state = wallet.node.accounts.get_mut(&AccountId::new(id)).unwrap();
            state.program_owner = programs::token().id();
            state.data = (&holding).into();
        };
        set(
            &mut wallet,
            from,
            token_core::TokenHolding::NftPrintedCopy {
                definition_id: collection,
                owned: true,
            },
        );
        set(
            &mut wallet,
            [2; 32],
            token_core::TokenHolding::NftPrintedCopy {
                definition_id: collection,
                owned: false,
            },
        );
        let transfer = |collection| token::NftTransfer {
            from,
            to: [2; 32],
            collection,
        };
        assert!(
            wallet
                .prepare_nft(&mut policy, &app, transfer([9; 32]), 100)
                .is_err()
        );
        let prepared = wallet
            .prepare_nft(&mut policy, &app, transfer(*collection.value()), 100)
            .unwrap();
        assert!(
            wallet
                .execute(&mut policy, &app, &prepared, &key, 100)
                .is_err()
        );
        assert!(wallet.node.sent.borrow().is_empty());
        policy.decide(prepared.prompt().id, true, 100).unwrap();
        wallet
            .execute(&mut policy, &app, &prepared, &key, 100)
            .unwrap();
        assert!(
            wallet
                .execute(&mut policy, &app, &prepared, &key, 100)
                .is_err()
        );
        set(
            &mut wallet,
            [2; 32],
            token_core::TokenHolding::NftPrintedCopy {
                definition_id: collection,
                owned: true,
            },
        );
        assert!(
            wallet
                .prepare_nft(&mut policy, &app, transfer(*collection.value()), 100)
                .is_err()
        );
        set(
            &mut wallet,
            from,
            token_core::TokenHolding::NftMaster {
                definition_id: collection,
                print_balance: 4,
            },
        );
        assert!(
            wallet
                .prepare_nft(&mut policy, &app, transfer(*collection.value()), 100)
                .is_err()
        );
        set(
            &mut wallet,
            [2; 32],
            token_core::TokenHolding::NftMaster {
                definition_id: collection,
                print_balance: 0,
            },
        );
        let prepared = wallet
            .prepare_nft(&mut policy, &app, transfer(*collection.value()), 100)
            .unwrap();
        let Request::Transaction(request) = &prepared.prompt.request else {
            panic!()
        };
        assert!(
            matches!(&request.effects[1], Effect::ContractCall { explanation, .. } if explanation.contains("all 3 remaining print rights"))
        );
        wallet
            .node
            .accounts
            .get_mut(&AccountId::new([2; 32]))
            .unwrap()
            .program_owner = programs::authenticated_transfer().id();
        assert!(
            wallet
                .prepare_nft(&mut policy, &app, transfer(*collection.value()), 100)
                .is_err()
        );
        policy
            .set_grant(
                app.clone(),
                Grant {
                    accounts: [from].into_iter().collect(),
                    scopes: [Scope::CollectionProof].into_iter().collect(),
                },
            )
            .unwrap();
        assert!(
            wallet
                .prepare_nft(&mut policy, &app, transfer(*collection.value()), 100)
                .is_err()
        );
        assert!(wallet.public_nft_holding(&policy, &app, from).is_err());
        policy
            .set_grant(
                app.clone(),
                Grant {
                    accounts: [from].into_iter().collect(),
                    scopes: [Scope::NftEnumeration].into_iter().collect(),
                },
            )
            .unwrap();
        assert!(matches!(
            wallet.public_nft_holding(&policy, &app, from).unwrap(),
            token_core::TokenHolding::NftMaster {
                print_balance: 4,
                ..
            }
        ));
        assert!(wallet.public_nft_holding(&policy, &app, [2; 32]).is_err());
    }
    #[test]
    fn token_initialization_requires_real_definition_and_unused_account() {
        let (mut wallet, mut policy, app, _, from) = fixture();
        let definition = [2; 32];
        let state = wallet
            .node
            .accounts
            .get_mut(&AccountId::new(definition))
            .unwrap();
        state.program_owner = programs::token().id();
        state.data = (&token_core::TokenDefinition::Fungible {
            name: "fixture".into(),
            total_supply: 10,
            metadata_id: None,
        })
            .into();
        assert!(
            wallet
                .prepare_token_initialize(&mut policy, &app, from, definition, 100)
                .is_err()
        );
        wallet
            .node
            .accounts
            .insert(AccountId::new(from), lee::Account::default());
        assert!(
            wallet
                .prepare_token_initialize(&mut policy, &app, from, definition, 100)
                .is_ok()
        );
        wallet
            .node
            .accounts
            .get_mut(&AccountId::new(definition))
            .unwrap()
            .program_owner = programs::authenticated_transfer().id();
        assert!(
            wallet
                .prepare_token_initialize(&mut policy, &app, from, definition, 100)
                .is_err()
        );
        assert!(
            wallet
                .prepare_token_initialize(&mut policy, &app, from, from, 100)
                .is_err()
        );
    }
    #[test]
    fn fungible_effects_match_chain_data_and_require_approval() {
        let (mut wallet, mut policy, app, key, from) = fixture();
        let asset = [8; 32];
        for (id, balance) in [(from, 100), ([2; 32], 0)] {
            let state = wallet.node.accounts.get_mut(&AccountId::new(id)).unwrap();
            state.program_owner = programs::token().id();
            state.data = (&token_core::TokenHolding::Fungible {
                definition_id: AccountId::new(asset),
                balance,
            })
                .into();
        }
        let transfer = |asset, amount| token::FungibleTransfer {
            from,
            to: [2; 32],
            asset,
            amount,
        };
        assert!(
            wallet
                .prepare_fungible(&mut policy, &app, transfer([9; 32], 1), 100)
                .is_err()
        );
        assert!(
            wallet
                .prepare_fungible(&mut policy, &app, transfer(asset, 101), 100)
                .is_err()
        );
        let prepared = wallet
            .prepare_fungible(&mut policy, &app, transfer(asset, 25), 100)
            .unwrap();
        let Request::Transaction(request) = &prepared.prompt().request else {
            panic!()
        };
        assert_eq!(
            request.effects,
            vec![Effect::TokenTransfer {
                asset,
                amount: "25".into(),
                destination: [2; 32]
            }]
        );
        assert!(
            wallet
                .execute(&mut policy, &app, &prepared, &key, 100)
                .is_err()
        );
        assert!(wallet.node.sent.borrow().is_empty());
        policy.decide(prepared.prompt().id, true, 100).unwrap();
        wallet
            .execute(&mut policy, &app, &prepared, &key, 100)
            .unwrap();
        assert_eq!(wallet.node.sent.borrow().len(), 1);
        assert!(
            wallet
                .execute(&mut policy, &app, &prepared, &key, 100)
                .is_err()
        );
        let recipient = wallet
            .node
            .accounts
            .get_mut(&AccountId::new([2; 32]))
            .unwrap();
        recipient.data = (&token_core::TokenHolding::NftPrintedCopy {
            definition_id: AccountId::new(asset),
            owned: false,
        })
            .into();
        assert!(
            wallet
                .prepare_fungible(&mut policy, &app, transfer(asset, 1), 100)
                .is_err()
        );
        assert!(wallet.fungible_balance(&policy, &app, from).is_err());
    }
    #[test]
    fn exact_effects_need_explicit_approval_and_cannot_be_replayed() {
        let (wallet, mut policy, app, key, from) = fixture();
        let prepared = wallet
            .prepare_native(
                &mut policy,
                &app,
                NativeTransfer {
                    from,
                    to: [2; 32],
                    amount: 25,
                },
                100,
            )
            .unwrap();
        assert!(
            wallet
                .execute(&mut policy, &app, &prepared, &key, 100)
                .is_err()
        );
        assert!(wallet.node.sent.borrow().is_empty());
        let Request::Transaction(tx) = &prepared.prompt().request else {
            panic!()
        };
        assert_eq!(
            tx.effects,
            vec![Effect::NativeTransfer {
                amount: "25".into(),
                destination: [2; 32]
            }]
        );
        policy.decide(prepared.prompt().id, true, 101).unwrap();
        wallet
            .execute(&mut policy, &app, &prepared, &key, 102)
            .unwrap();
        assert_eq!(wallet.node.sent.borrow().len(), 1);
        assert!(
            wallet
                .execute(&mut policy, &app, &prepared, &key, 103)
                .is_err()
        );
    }
    #[test]
    fn node_switch_and_revocation_fail_before_signing() {
        let (mut wallet, mut policy, app, key, from) = fixture();
        assert!(wallet.public_balance(&policy, &app, from).is_err());
        let prepared = wallet
            .prepare_native(
                &mut policy,
                &app,
                NativeTransfer {
                    from,
                    to: [2; 32],
                    amount: 25,
                },
                100,
            )
            .unwrap();
        policy.decide(prepared.prompt().id, true, 100).unwrap();
        wallet.endpoint = "http://127.0.0.1:2".into();
        assert!(
            wallet
                .execute(&mut policy, &app, &prepared, &key, 101)
                .is_err()
        );
        wallet.endpoint = "http://127.0.0.1:1".into();
        policy.revoke(&app);
        assert!(
            wallet
                .execute(&mut policy, &app, &prepared, &key, 101)
                .is_err()
        );
        assert!(wallet.node.sent.borrow().is_empty());
    }
    #[test]
    fn uncertain_submission_preserves_hash_and_consumes_approval() {
        let (mut wallet, mut policy, app, key, from) = fixture();
        wallet.node.lose_response = true;
        let prepared = wallet
            .prepare_native(
                &mut policy,
                &app,
                NativeTransfer {
                    from,
                    to: [2; 32],
                    amount: 25,
                },
                100,
            )
            .unwrap();
        policy.decide(prepared.prompt().id, true, 100).unwrap();
        let Error::Submission { hash, .. } = wallet
            .execute(&mut policy, &app, &prepared, &key, 101)
            .unwrap_err()
        else {
            panic!("Expected recoverable transaction hash")
        };
        assert_eq!(hash, wallet.node.sent.borrow()[0].hash());
        assert!(
            wallet
                .execute(&mut policy, &app, &prepared, &key, 102)
                .is_err()
        );
        assert_eq!(wallet.node.sent.borrow().len(), 1);
    }
}
