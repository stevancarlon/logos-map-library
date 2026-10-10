// SPDX-License-Identifier: MIT OR Apache-2.0
//! Native transfers using upstream v0.3 messages and one-use wallet approvals.
use crate::{AccountId, AccountView, Error, FeeQuote, NATIVE_PROGRAM, Node, Result, ShardSelector};
use lee_core_v03::{account::ProgramShardSelector, native_token::Instruction};
use lee_v03::{
    PrivateKey, PublicKey, PublicTransaction,
    fees::FeeDeclaration,
    public_transaction::{Message, WitnessSet},
};
use logos_wallet_policy::{AppId, Effect, Policy, Prompt, Request, Scope, Transaction};
use sha2::{Digest, Sha256};

pub trait NativeReader {
    fn native_view(&self, account: AccountId) -> Result<AccountView>;
    fn fees(&self) -> Result<FeeQuote>;
}
impl<T: NativeReader + ?Sized> NativeReader for &T {
    fn native_view(&self, account: AccountId) -> Result<AccountView> {
        (**self).native_view(account)
    }
    fn fees(&self) -> Result<FeeQuote> {
        (**self).fees()
    }
}
impl NativeReader for Node {
    fn native_view(&self, account: AccountId) -> Result<AccountView> {
        self.account_view(&ShardSelector {
            account_id: account,
            program_account_id: NATIVE_PROGRAM,
        })
    }
    fn fees(&self) -> Result<FeeQuote> {
        self.fee_quote()
    }
}
#[derive(Clone, Copy)]
pub struct NativeTransfer {
    pub from: AccountId,
    pub to: AccountId,
    pub amount: u128,
    pub gas_limit: u64,
    pub tip: u64,
    /// Explicit user budget, never silently raised from a node quote.
    pub max_fee: u128,
}
pub struct PreparedTransfer {
    message: Message,
    prompt: Prompt,
    transfer: NativeTransfer,
    wire_bytes: u64,
}
impl PreparedTransfer {
    pub(crate) fn sender(&self) -> AccountId {
        self.transfer.from
    }
    pub fn prompt(&self) -> &Prompt {
        &self.prompt
    }
    pub fn wire_bytes(&self) -> u64 {
        self.wire_bytes
    }
}
pub struct Wallet<R> {
    reader: R,
    endpoint: String,
}
impl<R: NativeReader> Wallet<R> {
    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }
    pub fn new(reader: R, endpoint: &str) -> Result<Self> {
        // Apply the same endpoint syntax rules as the network adapter.
        let _ = Node::new(endpoint)?;
        Ok(Self {
            reader,
            endpoint: endpoint.trim_end_matches('/').into(),
        })
    }
    pub fn prepare_native(
        &self,
        policy: &mut Policy,
        app: &AppId,
        transfer: NativeTransfer,
        now: u64,
    ) -> Result<PreparedTransfer> {
        if !policy.permitted(app, Scope::Transactions, Some(transfer.from.bytes())) {
            return Err(Error::Invalid("transaction permission denied"));
        }
        if transfer.amount == 0 || transfer.from == transfer.to || transfer.gas_limit == 0 {
            return Err(Error::Invalid(
                "positive amount and gas limit with distinct recipient required",
            ));
        }
        let sender = self.reader.native_view(transfer.from)?;
        let recipient = self.reader.native_view(transfer.to)?;
        validate_balances(&sender, &recipient, transfer)?;
        if sender.nonce == u128::MAX {
            return Err(Error::Invalid("sender nonce exhausted"));
        }
        let from = upstream(transfer.from);
        let message = Message::try_new_with_fees(
            lee_core_v03::native_token::NATIVE_TOKEN_PROGRAM_ID,
            vec![
                ProgramShardSelector::native_balance(from),
                ProgramShardSelector::native_balance(upstream(transfer.to)),
            ],
            vec![sender.nonce.into()],
            Instruction::Transfer {
                amount: transfer.amount,
            },
            FeeDeclaration::new(from, transfer.gas_limit, transfer.tip, transfer.max_fee),
        )
        .map_err(|_| Error::Invalid("cannot encode native transfer"))?;
        // The public enum tag is one byte; one witness adds a 64-byte Schnorr
        // signature and 32-byte public key to the existing Borsh vector length.
        let unsigned = PublicTransaction::new(message.clone(), WitnessSet::from_raw_parts(vec![]));
        let wire_bytes = u64::try_from(
            borsh::to_vec(&unsigned)
                .map_err(|_| Error::Invalid("cannot size transfer"))?
                .len(),
        )
        .map_err(|_| Error::Invalid("transaction too large"))?
        .checked_add(97)
        .ok_or(Error::Invalid("transaction size overflow"))?;
        let quote = self.reader.fees()?;
        validate_fees(
            &quote,
            transfer.gas_limit,
            transfer.tip,
            transfer.max_fee,
            wire_bytes,
        )?;
        let mut binding = Sha256::new();
        binding.update(b"logos-wallet-v03-native-approval-v1\0");
        binding.update((self.endpoint.len() as u64).to_le_bytes());
        binding.update(self.endpoint.as_bytes());
        binding.update(message.hash());
        let prompt = policy.request(app, Request::Transaction(Transaction {
            account: transfer.from.bytes(), message_hash: binding.finalize().into(), network: self.endpoint.clone(),
            effects: vec![Effect::NativeTransfer { amount: transfer.amount.to_string(), destination: transfer.to.bytes() },
                Effect::ContractCall { program: NATIVE_PROGRAM.bytes(), instruction: "v0.3 transaction fee".into(),
                    explanation: format!("Maximum total fee: {} native units, including tip {}. Gas limit: {}. Fee quote block: {}. The sender pays. This is an approved cap, not a prediction of the final fee.",transfer.max_fee,transfer.tip,transfer.gas_limit,quote.height) }],
        }), now)?;
        Ok(PreparedTransfer {
            message,
            prompt,
            transfer,
            wire_bytes,
        })
    }
    /// Requires the trusted wallet to approve the exact prompt first. Returns
    /// signed upstream bytes for durable outbox storage; never broadcasts.
    pub fn sign_approved(
        &self,
        policy: &mut Policy,
        app: &AppId,
        prepared: &PreparedTransfer,
        key: &PrivateKey,
        now: u64,
    ) -> Result<PublicTransaction> {
        let Request::Transaction(request) = &prepared.prompt.request else {
            return Err(Error::Invalid("transaction approval required"));
        };
        let transfer = prepared.transfer;
        if request.network != self.endpoint
            || request.account != transfer.from.bytes()
            || lee_v03::AccountId::from(&PublicKey::new_from_private_key(key))
                != upstream(transfer.from)
            || !policy.permitted(app, Scope::Transactions, Some(transfer.from.bytes()))
        {
            return Err(Error::Invalid(
                "signer, permission or endpoint differs from approval",
            ));
        }
        let sender = self.reader.native_view(transfer.from)?;
        let recipient = self.reader.native_view(transfer.to)?;
        if prepared.message.nonces != vec![sender.nonce.into()] {
            return Err(Error::Invalid("nonce changed; create a new review"));
        }
        validate_balances(&sender, &recipient, transfer)?;
        validate_fees(
            &self.reader.fees()?,
            transfer.gas_limit,
            transfer.tip,
            transfer.max_fee,
            prepared.wire_bytes,
        )?;
        policy.consume(app, prepared.prompt.id, &prepared.prompt.request, now)?;
        let witness = WitnessSet::for_message(&prepared.message, &[key]);
        if !witness.is_valid_for(&prepared.message) {
            return Err(Error::Invalid("signature verification failed"));
        }
        Ok(PublicTransaction::new(prepared.message.clone(), witness))
    }
}
fn upstream(id: AccountId) -> lee_v03::AccountId {
    lee_v03::AccountId::new(id.bytes())
}
fn validate_balances(
    sender: &AccountView,
    recipient: &AccountView,
    transfer: NativeTransfer,
) -> Result<()> {
    let total = transfer
        .amount
        .checked_add(transfer.max_fee)
        .ok_or(Error::Invalid("amount plus fee overflow"))?;
    if sender.native_balance()? < total {
        return Err(Error::Invalid(
            "insufficient balance for amount and maximum fee",
        ));
    }
    recipient
        .native_balance()?
        .checked_add(transfer.amount)
        .ok_or(Error::Invalid("recipient balance overflow"))?;
    Ok(())
}
pub(crate) fn validate_fees(
    quote: &FeeQuote,
    gas_limit: u64,
    tip: u64,
    max_fee: u128,
    wire_bytes: u64,
) -> Result<()> {
    quote.validate()?;
    if gas_limit > quote.max_gas_exec || wire_bytes > quote.max_gas_stor {
        return Err(Error::Invalid("transaction exceeds quoted gas caps"));
    }
    let exec = u128::from(gas_limit)
        * u128::from(quote.base_fee_exec.max(quote.next_base_fee_exec_ceiling));
    let storage = u128::from(wire_bytes)
        * u128::from(quote.base_fee_stor.max(quote.next_base_fee_stor_ceiling));
    let reserve = exec
        .checked_add(storage)
        .and_then(|value| value.checked_add(u128::from(tip)))
        .ok_or(Error::Invalid("fee reserve overflow"))?;
    if max_fee < reserve {
        return Err(Error::Invalid(
            "fee quote exceeds approved budget; create a new review",
        ));
    }
    Ok(())
}
