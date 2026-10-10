// SPDX-License-Identifier: MIT OR Apache-2.0
//! Public transfers for the pinned v0.3 reference token program.
use crate::{
    AccountId, AccountView, Error, Node, Result, ShardSelector, deployment,
    transfer::{NativeReader, validate_fees},
};
use lee_core_v03::account::ProgramShardSelector;
use lee_v03::{
    PrivateKey, PublicKey, PublicTransaction,
    fees::FeeDeclaration,
    public_transaction::{Message, WitnessSet},
};
use logos_wallet_policy::{AppId, Effect, Policy, Prompt, Request, Scope, Transaction};
use sha2::{Digest, Sha256};
pub use token_core_v03::{TokenDefinition, TokenDescriptor, TokenHolding, TokenKind};

// The official pinned v0.3 guest image; also independently reconstructed from
// public-testnet loader segments in evidence/lez-v03-deployment-read.json.
pub const IMAGE: [u32; 8] = [
    742469009, 2781184622, 3496626878, 3713569652, 1701438085, 2132033625, 373050663, 2870233740,
];
pub fn program() -> AccountId {
    AccountId::from_bytes(*token_core_v03::token_account_id().value())
}
pub trait TokenReader: NativeReader {
    fn token_view(&self, account: AccountId) -> Result<AccountView>;
    fn verify_token_program(&self) -> Result<()>;
}
impl<T: TokenReader + ?Sized> TokenReader for &T {
    fn token_view(&self, account: AccountId) -> Result<AccountView> {
        (**self).token_view(account)
    }
    fn verify_token_program(&self) -> Result<()> {
        (**self).verify_token_program()
    }
}
impl TokenReader for Node {
    fn token_view(&self, account: AccountId) -> Result<AccountView> {
        self.account_view(&ShardSelector {
            account_id: account,
            program_account_id: program(),
        })
    }
    fn verify_token_program(&self) -> Result<()> {
        let observed = deployment::inspect(self, program(), IMAGE)?;
        if !observed.immutable {
            return Err(Error::Invalid("reference token program must be immutable"));
        }
        Ok(())
    }
}
fn data(view: &AccountView) -> Result<&[u8]> {
    view.validate_projection(&ShardSelector {
        account_id: AccountId::from_bytes([0; 32]),
        program_account_id: program(),
    })?;
    Ok(view
        .data
        .shards
        .get(&program())
        .map(Vec::as_slice)
        .unwrap_or_default())
}
pub fn holding(view: &AccountView) -> Result<Option<TokenHolding>> {
    let bytes = data(view)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    Ok(Some(borsh::from_slice(bytes).map_err(|_| {
        Error::Invalid("invalid token holding shard")
    })?))
}
pub fn definition(view: &AccountView) -> Result<TokenDefinition> {
    borsh::from_slice(data(view)?).map_err(|_| Error::Invalid("invalid token definition shard"))
}
#[derive(Clone, Copy)]
pub struct TokenTransfer {
    pub from: AccountId,
    pub to: AccountId,
    pub definition: AccountId,
    pub kind: TokenKind,
    /// Fungible units, one printed copy, or the entire master print counter.
    pub amount: u128,
    pub gas_limit: u64,
    pub tip: u64,
    pub max_fee: u128,
}
pub struct PreparedTokenTransfer {
    message: Message,
    prompt: Prompt,
    transfer: TokenTransfer,
    wire_bytes: u64,
}
impl PreparedTokenTransfer {
    pub fn prompt(&self) -> &Prompt {
        &self.prompt
    }
    pub(crate) fn sender(&self) -> AccountId {
        self.transfer.from
    }
}
pub struct TokenWallet<R> {
    reader: R,
    endpoint: String,
}
impl<R: TokenReader> TokenWallet<R> {
    pub fn new(reader: R, endpoint: &str) -> Result<Self> {
        Node::new(endpoint)?;
        Ok(Self {
            reader,
            endpoint: endpoint.trim_end_matches('/').into(),
        })
    }
    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }
    fn validate_state(&self, t: TokenTransfer) -> Result<u128> {
        self.reader.verify_token_program()?;
        let native = self.reader.native_view(t.from)?;
        let sender = self.reader.token_view(t.from)?;
        if native.nonce != sender.nonce || native.nonce == u128::MAX {
            return Err(Error::Invalid("inconsistent or exhausted sender nonce"));
        }
        if native.native_balance()? < t.max_fee {
            return Err(Error::Invalid(
                "insufficient native balance for token fee cap",
            ));
        }
        let sender = holding(&sender)?.ok_or(Error::Invalid("sender has no token holding"))?;
        let recipient = holding(&self.reader.token_view(t.to)?)?;
        let definition = definition(&self.reader.token_view(t.definition)?)?;
        validate_holdings(t, &definition, &sender, recipient.as_ref())?;
        Ok(native.nonce)
    }
    pub fn prepare(
        &self,
        policy: &mut Policy,
        app: &AppId,
        t: TokenTransfer,
        now: u64,
    ) -> Result<PreparedTokenTransfer> {
        if !policy.permitted(app, Scope::Transactions, Some(t.from.bytes())) {
            return Err(Error::Invalid("transaction permission denied"));
        }
        if t.amount == 0
            || t.gas_limit == 0
            || t.from == t.to
            || t.from == t.definition
            || t.to == t.definition
        {
            return Err(Error::Invalid(
                "invalid token transfer accounts, amount or gas",
            ));
        }
        let nonce = self.validate_state(t)?;
        let message = Message::try_new_with_fees(
            token_core_v03::token_account_id(),
            vec![t.from, t.to]
                .into_iter()
                .map(|id| ProgramShardSelector {
                    account_id: upstream(id),
                    program_account_id: token_core_v03::token_account_id(),
                })
                .collect(),
            vec![nonce.into()],
            token_core_v03::Instruction::Transfer {
                amount_to_transfer: t.amount,
                descriptor: TokenDescriptor {
                    definition_id: upstream(t.definition),
                    kind: t.kind,
                },
            },
            FeeDeclaration::new(upstream(t.from), t.gas_limit, t.tip, t.max_fee),
        )
        .map_err(|_| Error::Invalid("cannot encode token transfer"))?;
        let unsigned = PublicTransaction::new(message.clone(), WitnessSet::from_raw_parts(vec![]));
        let wire_bytes = u64::try_from(
            borsh::to_vec(&unsigned)
                .map_err(|_| Error::Invalid("cannot size token transfer"))?
                .len(),
        )
        .map_err(|_| Error::Invalid("token transfer too large"))?
            + 97;
        let quote = self.reader.fees()?;
        validate_fees(&quote, t.gas_limit, t.tip, t.max_fee, wire_bytes)?;
        let effect = match t.kind {
            TokenKind::Fungible => Effect::TokenTransfer {
                asset: t.definition.bytes(),
                amount: t.amount.to_string(),
                destination: t.to.bytes(),
            },
            TokenKind::NftPrintedCopy => Effect::NftTransfer {
                collection: t.definition.bytes(),
                token: t.from.bytes(),
                destination: t.to.bytes(),
            },
            TokenKind::NftMaster => Effect::ContractCall {
                program: program().bytes(),
                instruction: "Transfer NFT master".into(),
                explanation: format!(
                    "Move the master for collection {} to {} with all {} remaining print rights (counter {}). The holding account is not a stable token serial.",
                    t.definition,
                    t.to,
                    t.amount - 1,
                    t.amount
                ),
            },
        };
        let mut digest = Sha256::new();
        digest.update(b"logos-wallet-v03-token-approval-v1\0");
        digest.update((self.endpoint.len() as u64).to_le_bytes());
        digest.update(self.endpoint.as_bytes());
        digest.update(message.hash());
        let prompt=policy.request(app,Request::Transaction(Transaction {account:t.from.bytes(),message_hash:digest.finalize().into(),network:self.endpoint.clone(),effects:vec![effect,
            Effect::ContractCall {program:program().bytes(),instruction:"v0.3 token transfer and fee".into(),explanation:format!("Reference token program {}. Maximum fee {} native units including tip {}; gas limit {}; quote block {}. Recipient's empty token shard is initialized automatically. This is a public transfer. Printed-copy holding addresses are not stable token serials.",program(),t.max_fee,t.tip,t.gas_limit,quote.height)}]}),now)?;
        Ok(PreparedTokenTransfer {
            message,
            prompt,
            transfer: t,
            wire_bytes,
        })
    }
    pub fn sign_approved(
        &self,
        policy: &mut Policy,
        app: &AppId,
        prepared: &PreparedTokenTransfer,
        key: &PrivateKey,
        now: u64,
    ) -> Result<PublicTransaction> {
        let t = prepared.transfer;
        let Request::Transaction(request) = &prepared.prompt.request else {
            return Err(Error::Invalid("token approval required"));
        };
        if request.network != self.endpoint
            || !policy.permitted(app, Scope::Transactions, Some(t.from.bytes()))
            || lee_v03::AccountId::from(&PublicKey::new_from_private_key(key)) != upstream(t.from)
        {
            return Err(Error::Invalid(
                "token signer, permission or endpoint differs from approval",
            ));
        }
        let nonce = self.validate_state(t)?;
        if prepared.message.nonces != vec![nonce.into()] {
            return Err(Error::Invalid(
                "token sender nonce changed; create a new review",
            ));
        }
        validate_fees(
            &self.reader.fees()?,
            t.gas_limit,
            t.tip,
            t.max_fee,
            prepared.wire_bytes,
        )?;
        policy.consume(app, prepared.prompt.id, &prepared.prompt.request, now)?;
        let witness = WitnessSet::for_message(&prepared.message, &[key]);
        if !witness.is_valid_for(&prepared.message) {
            return Err(Error::Invalid("token signature verification failed"));
        }
        Ok(PublicTransaction::new(prepared.message.clone(), witness))
    }
}
fn upstream(id: AccountId) -> lee_v03::AccountId {
    lee_v03::AccountId::new(id.bytes())
}
fn validate_holdings(
    t: TokenTransfer,
    definition: &TokenDefinition,
    sender: &TokenHolding,
    recipient: Option<&TokenHolding>,
) -> Result<()> {
    if sender.kind() != t.kind
        || sender.definition_id() != upstream(t.definition)
        || recipient
            .is_some_and(|r| r.kind() != t.kind || r.definition_id() != upstream(t.definition))
    {
        return Err(Error::Invalid("token kind or collection mismatch"));
    }
    if !matches!(
        (definition, t.kind),
        (TokenDefinition::Fungible { .. }, TokenKind::Fungible)
            | (
                TokenDefinition::NonFungible { .. },
                TokenKind::NftMaster | TokenKind::NftPrintedCopy
            )
    ) {
        return Err(Error::Invalid("token definition kind mismatch"));
    }
    match (sender, recipient) {
        (TokenHolding::Fungible { balance, .. }, recipient) => {
            let dest = match recipient {
                Some(TokenHolding::Fungible { balance, .. }) => *balance,
                _ => 0,
            };
            if *balance < t.amount || dest.checked_add(t.amount).is_none() {
                return Err(Error::Invalid("token balance or recipient overflow"));
            }
        }
        (TokenHolding::NftPrintedCopy { owned, .. }, recipient) => {
            if t.amount != 1
                || !owned
                || matches!(
                    recipient,
                    Some(TokenHolding::NftPrintedCopy { owned: true, .. })
                )
            {
                return Err(Error::Invalid("printed NFT ownership or amount mismatch"));
            }
        }
        (TokenHolding::NftMaster { print_balance, .. }, recipient) => {
            if *print_balance != t.amount
                || t.amount == 0
                || matches!(
                    recipient,
                    Some(TokenHolding::NftMaster {
                        print_balance: 1..,
                        ..
                    })
                )
            {
                return Err(Error::Invalid(
                    "master transfer must move all print rights into an empty holding",
                ));
            }
        }
    }
    Ok(())
}
