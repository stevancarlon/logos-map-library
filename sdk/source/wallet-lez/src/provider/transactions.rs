// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::{
    NativeTransfer, PreparedTransfer,
    keyring::public_outbox::SubmissionStatus,
    token::{FungibleTransfer, NftTransfer},
};
use logos_registry_sdk::verification::SourceReview;
use logos_wallet_policy::{Prompt, Request};

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TransactionProposal {
    InitializeTestimonials {
        account: lee::AccountId,
    },
    CreateTestimonialPage {
        account: lee::AccountId,
        number: u64,
    },
    PublishTestimonial {
        account: lee::AccountId,
        content: logos_testimonial::Content,
    },
    NativeTransfer {
        from: lee::AccountId,
        to: lee::AccountId,
        amount: String,
    },
    FungibleTransfer {
        from: lee::AccountId,
        to: lee::AccountId,
        definition: lee::AccountId,
        amount: String,
    },
    NftTransfer {
        from: lee::AccountId,
        to: lee::AccountId,
        collection: lee::AccountId,
    },
    NftTransferToNewHolding {
        from: lee::AccountId,
        to: lee::AccountId,
        collection: lee::AccountId,
    },
    InitializeNative {
        account: lee::AccountId,
    },
    InitializeToken {
        holding: lee::AccountId,
        definition: lee::AccountId,
    },
    ClaimVault {
        account: lee::AccountId,
        amount: String,
    },
}
impl TransactionProposal {
    fn account(&self) -> lee::AccountId {
        match self {
            Self::NativeTransfer { from, .. }
            | Self::FungibleTransfer { from, .. }
            | Self::NftTransfer { from, .. }
            | Self::NftTransferToNewHolding { from, .. } => *from,
            Self::InitializeNative { account }
            | Self::ClaimVault { account, .. }
            | Self::InitializeTestimonials { account }
            | Self::CreateTestimonialPage { account, .. }
            | Self::PublishTestimonial { account, .. } => *account,
            Self::InitializeToken { holding, .. } => *holding,
        }
    }
    fn signing_accounts(&self) -> Vec<lee::AccountId> {
        if let Self::NftTransferToNewHolding { from, to, .. } = self {
            vec![*from, *to]
        } else {
            vec![self.account()]
        }
    }
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TransactionState {
    Pending,
    Rejected,
    Submission { submission: SubmissionStatus },
    Failed { message: String },
}
pub(super) struct TransactionRecord {
    principal: Principal,
    expires_at: u64,
    prepared: Option<PreparedTransfer>,
    state: TransactionState,
    source_verification: SourceReview,
    // Isolated authority for a local owner action; never becomes a dApp grant.
    owner_policy: Option<Policy>,
}
#[derive(Serialize)]
pub struct TransactionPrompt {
    pub id: String,
    pub principal: Principal,
    pub approval: Prompt,
    pub source_verification: SourceReview,
}
fn amount(value: &str) -> Result<u128> {
    if value.is_empty() || value.len() > 39 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidRequest);
    }
    value
        .parse::<u128>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or(Error::InvalidRequest)
}
impl Provider {
    pub(super) fn prune_transactions(&mut self, now: u64) {
        self.transactions
            .retain(|_, record| record.expires_at > now);
    }
    pub(super) fn cancel_transactions(&mut self, caller: Option<&Principal>) {
        self.cancel_matching_transactions(caller, None);
    }
    pub(super) fn cancel_account_transactions(
        &mut self,
        caller: &Principal,
        account: lee::AccountId,
    ) {
        self.cancel_matching_transactions(Some(caller), Some(account));
    }
    fn cancel_matching_transactions(
        &mut self,
        caller: Option<&Principal>,
        account: Option<lee::AccountId>,
    ) {
        self.transactions.retain(|_, record| {
            if account.is_some_and(|account| {
                record
                    .prepared
                    .as_ref()
                    .is_none_or(|prepared| !prepared.signing_accounts().contains(&account))
            }) {
                return true;
            }
            if caller.is_none_or(|caller| caller == &record.principal) && record.prepared.is_some()
            {
                if let Some(prepared) = record.prepared.take() {
                    let policy = record.owner_policy.as_mut().unwrap_or(&mut self.policy);
                    let _ = policy.decide(prepared.prompt().id, false, 0);
                }
                return false;
            }
            true
        });
    }
    pub fn propose_transaction<N: Node>(
        &mut self,
        caller: &Principal,
        wallet: &NativeWallet<N>,
        proposal: TransactionProposal,
        now: u64,
    ) -> Result<String> {
        self.prune_transactions(now);
        for account in proposal.signing_accounts() {
            self.ensure_public_access(caller, Scope::Transactions, account)?;
        }
        if self.transactions.len() >= 128 {
            return Err(Error::QueueFull);
        }
        let mut nonce = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Randomness)?;
        let id: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        if self.transactions.contains_key(&id) {
            return Err(Error::Randomness);
        }
        let app = caller.policy_id()?;
        let prepared = match proposal {
            TransactionProposal::InitializeTestimonials { account } => wallet.prepare_testimonial(
                &mut self.policy,
                &app,
                *account.value(),
                crate::testimonial::Action::Initialize,
                now,
            )?,
            TransactionProposal::CreateTestimonialPage { account, number } => wallet
                .prepare_testimonial(
                    &mut self.policy,
                    &app,
                    *account.value(),
                    crate::testimonial::Action::CreatePage { number },
                    now,
                )?,
            TransactionProposal::PublishTestimonial { account, content } => wallet
                .prepare_testimonial(
                    &mut self.policy,
                    &app,
                    *account.value(),
                    crate::testimonial::Action::Publish(content),
                    now,
                )?,

            TransactionProposal::NativeTransfer {
                from,
                to,
                amount: value,
            } => wallet.prepare_native(
                &mut self.policy,
                &app,
                NativeTransfer {
                    from: *from.value(),
                    to: *to.value(),
                    amount: amount(&value)?,
                },
                now,
            )?,
            TransactionProposal::FungibleTransfer {
                from,
                to,
                definition,
                amount: value,
            } => wallet.prepare_fungible(
                &mut self.policy,
                &app,
                FungibleTransfer {
                    from: *from.value(),
                    to: *to.value(),
                    asset: *definition.value(),
                    amount: amount(&value)?,
                },
                now,
            )?,
            TransactionProposal::NftTransfer {
                from,
                to,
                collection,
            } => wallet.prepare_nft(
                &mut self.policy,
                &app,
                NftTransfer {
                    from: *from.value(),
                    to: *to.value(),
                    collection: *collection.value(),
                },
                now,
            )?,
            TransactionProposal::InitializeNative { account } => {
                wallet.prepare_initialize(&mut self.policy, &app, *account.value(), now)?
            }
            TransactionProposal::NftTransferToNewHolding {
                from,
                to,
                collection,
            } => wallet.prepare_nft_to_new_holding(
                &mut self.policy,
                &app,
                NftTransfer {
                    from: *from.value(),
                    to: *to.value(),
                    collection: *collection.value(),
                },
                now,
            )?,
            TransactionProposal::InitializeToken {
                holding,
                definition,
            } => wallet.prepare_token_initialize(
                &mut self.policy,
                &app,
                *holding.value(),
                *definition.value(),
                now,
            )?,
            TransactionProposal::ClaimVault {
                account,
                amount: value,
            } => wallet.prepare_claim(
                &mut self.policy,
                &app,
                *account.value(),
                amount(&value)?,
                now,
            )?,
        };
        let program = logos_registry_sdk::program_bytes(&prepared.message.program_id);
        let source_verification = self.source_review.as_ref().map_or_else(
            || SourceReview::unchecked(&program),
            |config| config.inspect(&wallet.node, &wallet.endpoint, &program),
        );
        self.transactions.insert(
            id.clone(),
            TransactionRecord {
                principal: caller.clone(),
                expires_at: prepared.prompt().expires_at,
                prepared: Some(prepared),
                state: TransactionState::Pending,
                source_verification,
                owner_policy: None,
            },
        );
        Ok(id)
    }
    /// Local wallet action only. A temporary per-request policy lets the owner
    /// reuse normal preparation without granting the wallet UI dApp privileges.
    pub(crate) fn propose_owner_transaction<N: Node>(
        &mut self,
        wallet: &NativeWallet<N>,
        proposal: TransactionProposal,
        now: u64,
    ) -> Result<String> {
        self.keyring.ensure_current()?;
        let signing_accounts = proposal.signing_accounts();
        let owned = self.keyring.accounts()?;
        for account in &signing_accounts {
            if !owned
                .iter()
                .any(|info| info.account == *account && info.privacy == "public")
            {
                return Err(Error::NotPublic);
            }
        }
        let owner = Principal::Module {
            name: super::native::OWNER_MODULE.into(),
            instance: String::new(),
        };
        let mut local = Policy::default();
        local.set_grant(
            owner.policy_id()?,
            Grant {
                accounts: signing_accounts
                    .iter()
                    .map(|account| *account.value())
                    .collect(),
                scopes: BTreeSet::from([Scope::Transactions]),
            },
        )?;
        let ordinary = std::mem::replace(&mut self.policy, local);
        let result = self.propose_transaction(&owner, wallet, proposal, now);
        let local = std::mem::replace(&mut self.policy, ordinary);
        let id = result?;
        self.transactions
            .get_mut(&id)
            .ok_or(Error::MissingRequest)?
            .owner_policy = Some(local);
        Ok(id)
    }
    /// Trusted UI only; amounts/effects come from the wallet's pinned decoders.
    /// Source information is captured at proposal and rechecked before signing.
    pub fn transaction_prompts(&mut self, now: u64) -> Vec<TransactionPrompt> {
        self.prune_transactions(now);
        self.transactions
            .iter()
            .filter_map(|(id, record)| {
                record.prepared.as_ref().map(|prepared| TransactionPrompt {
                    id: id.clone(),
                    principal: record.principal.clone(),
                    approval: prepared.prompt().clone(),
                    source_verification: record.source_verification.clone(),
                })
            })
            .collect()
    }
    pub fn transaction_status(
        &mut self,
        caller: &Principal,
        id: &str,
        now: u64,
    ) -> Result<TransactionState> {
        caller.validate()?;
        self.prune_transactions(now);
        // Durable status takes precedence over transient bookkeeping, including
        // after an acknowledgement could not be committed or after a restart.
        match self.keyring.public_submission(caller, id) {
            Ok(submission) => return Ok(TransactionState::Submission { submission }),
            Err(crate::keyring::Error::NotFound) => {}
            Err(error) => return Err(error.into()),
        }
        self.transactions
            .get(id)
            .filter(|record| &record.principal == caller)
            .map(|record| record.state.clone())
            .ok_or(Error::MissingRequest)
    }
    /// Trusted wallet UI only. There is no dApp approve/sign/execute route.
    pub fn decide_transaction<N: Node>(
        &mut self,
        id: &str,
        approved: bool,
        wallet: &NativeWallet<N>,
        now: u64,
    ) -> Result<TransactionState> {
        self.prune_transactions(now);
        self.keyring.ensure_current()?;
        let record = self
            .transactions
            .get_mut(id)
            .filter(|record| record.prepared.is_some())
            .ok_or(Error::MissingRequest)?;
        let prepared = record.prepared.take().ok_or(Error::MissingRequest)?;
        let policy = record.owner_policy.as_mut().unwrap_or(&mut self.policy);
        if !approved {
            policy.decide(prepared.prompt().id, false, now)?;
            record.state = TransactionState::Rejected;
            return Ok(record.state.clone());
        }
        // Consume this UI decision even if preflight/signing/persistence fails.
        // A retry must return to a fresh immutable prompt.
        record.state = TransactionState::Failed {
            message: "Approval execution did not complete; request a new review".into(),
        };
        let Request::Transaction(_) = &prepared.prompt().request else {
            return Err(Error::InvalidRequest);
        };
        let program = logos_registry_sdk::program_bytes(&prepared.message.program_id);
        let current_source = self.source_review.as_ref().map_or_else(
            || SourceReview::unchecked(&program),
            |config| config.inspect(&wallet.node, &wallet.endpoint, &program),
        );
        if current_source != record.source_verification {
            policy.decide(prepared.prompt().id, false, now)?;
            record.state = TransactionState::Failed {
                message: Error::SourceChanged.to_string(),
            };
            return Err(Error::SourceChanged);
        }
        let keys = prepared
            .signing_accounts()
            .iter()
            .map(|account| self.keyring.signing_key(*account))
            .collect::<crate::keyring::Result<Vec<_>>>()?;
        policy.decide(prepared.prompt().id, true, now)?;
        let signed = wallet.sign_approved_with_keys(
            policy,
            &record.principal.policy_id()?,
            &prepared,
            &keys.iter().collect::<Vec<_>>(),
            now,
        )?;
        let hash = self.keyring.retain_public_submission(
            id,
            &record.principal,
            &wallet.endpoint,
            signed.clone(),
        )?;
        let acknowledged = wallet
            .node
            .submit_transaction(&signed)
            .is_ok_and(|returned| returned == hash);
        // A failed write leaves the durable pre-broadcast record intact. Never
        // turn that into "not sent" or silently create a replacement transaction.
        self.keyring.mark_public_submission(id, acknowledged)?;
        let submission = self.keyring.public_submission(&record.principal, id)?;
        record.state = TransactionState::Submission { submission };
        Ok(record.state.clone())
    }
    /// Trusted UI convenience for the configured node. Moving the client out
    /// temporarily avoids retaining a shared borrow while consuming approval.
    pub fn decide_configured_transaction(
        &mut self,
        id: &str,
        approved: bool,
        now: u64,
    ) -> Result<TransactionState> {
        let wallet = self.network.take().ok_or(Error::NetworkNotConfigured)?;
        let result = self.decide_transaction(id, approved, &wallet, now);
        self.network = Some(wallet);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyring::public_outbox::SubmissionState;
    use logos_registry_sdk::AccountReader;
    use std::{
        cell::{Cell, RefCell},
        path::PathBuf,
    };
    const PASSWORD: &[u8] = b"provider outbox fixture";
    struct Memory {
        path: PathBuf,
        accounts: BTreeMap<lee::AccountId, lee::Account>,
        reads: Cell<usize>,
        submitted: RefCell<Vec<common::HashType>>,
        lose_response: Cell<bool>,
    }
    impl AccountReader for Memory {
        fn account(&self, id: lee::AccountId) -> logos_registry_sdk::Result<lee::Account> {
            self.reads.set(self.reads.get() + 1);
            self.accounts
                .get(&id)
                .cloned()
                .ok_or_else(|| logos_registry_sdk::Error::Invalid("Missing fixture".into()))
        }
    }
    impl Node for Memory {
        fn submit_transaction(
            &self,
            tx: &common::transaction::LeeTransaction,
        ) -> logos_registry_sdk::Result<common::HashType> {
            let common::transaction::LeeTransaction::Public(public) = tx else {
                panic!("expected public transaction")
            };
            assert!(public.witness_set.is_valid_for(&public.message));
            assert_eq!(
                public.witness_set.signatures_and_public_keys().len(),
                public.message.nonces.len()
            );
            // Prove ordering against the actual encrypted database, not a flag.
            let ring = Keyring::open(&self.path, PASSWORD).unwrap();
            assert!(
                ring.public_outbox()
                    .iter()
                    .any(|record| record.hash == tx.hash()
                        && record.state == SubmissionState::PreparedOrSubmissionUnknown)
            );
            self.submitted.borrow_mut().push(tx.hash());
            if self.lose_response.get() {
                Err(logos_registry_sdk::Error::Transport("response lost".into()))
            } else {
                Ok(tx.hash())
            }
        }
    }
    fn proposal(from: lee::AccountId, to: lee::AccountId, amount: &str) -> TransactionProposal {
        TransactionProposal::NativeTransfer {
            from,
            to,
            amount: amount.into(),
        }
    }
    #[test]
    fn recipient_claim_is_permission_gated_and_both_signatures_survive_outbox_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let mut ring = Keyring::create(&path, PASSWORD).unwrap();
        let from = ring.import_public("Master", &[1; 32]).unwrap();
        let to = ring.import_public("Fresh recipient", &[2; 32]).unwrap();
        let collection = lee::AccountId::new([8; 32]);
        let mut provider = Provider::unlocked(ring).unwrap();
        let app = Principal::Module {
            name: "master_test_app".into(),
            instance: String::new(),
        };
        let access = provider
            .request_access(&app, BTreeSet::from([Scope::Transactions]), 1)
            .unwrap();
        provider
            .decide_access(
                &access,
                Some(Grant {
                    accounts: BTreeSet::from([*from.value()]),
                    scopes: BTreeSet::from([Scope::Transactions]),
                }),
                2,
            )
            .unwrap();
        let wallet = NativeWallet {
            endpoint: "http://fixture.invalid".into(),
            node: Memory {
                path: path.clone(),
                accounts: BTreeMap::from([
                    (
                        from,
                        lee::Account {
                            program_owner: programs::token().id(),
                            data: (&token_core::TokenHolding::NftMaster {
                                definition_id: collection,
                                print_balance: 3,
                            })
                                .into(),
                            ..Default::default()
                        },
                    ),
                    (to, lee::Account::default()),
                ]),
                reads: Cell::new(0),
                submitted: RefCell::new(vec![]),
                lose_response: Cell::new(false),
            },
        };
        let proposal = || TransactionProposal::NftTransferToNewHolding {
            from,
            to,
            collection,
        };
        assert!(
            provider
                .propose_transaction(&app, &wallet, proposal(), 3)
                .is_err()
        );
        assert_eq!(wallet.node.reads.get(), 0);
        let access = provider
            .request_access(&app, BTreeSet::from([Scope::Transactions]), 4)
            .unwrap();
        provider
            .decide_access(
                &access,
                Some(Grant {
                    accounts: BTreeSet::from([*from.value(), *to.value()]),
                    scopes: BTreeSet::from([Scope::Transactions]),
                }),
                5,
            )
            .unwrap();
        let id = provider
            .propose_transaction(&app, &wallet, proposal(), 6)
            .unwrap();
        assert!(wallet.node.submitted.borrow().is_empty());
        let TransactionState::Submission { submission } =
            provider.decide_transaction(&id, true, &wallet, 7).unwrap()
        else {
            panic!()
        };
        assert_eq!(
            wallet.node.submitted.borrow().as_slice(),
            &[submission.hash]
        );
        assert!(provider.decide_transaction(&id, true, &wallet, 8).is_err());
        drop(provider);
        let mut restored = Provider::unlocked(Keyring::open(&path, PASSWORD).unwrap()).unwrap();
        let TransactionState::Submission {
            submission: reopened,
        } = restored.transaction_status(&app, &id, 9).unwrap()
        else {
            panic!()
        };
        assert_eq!(reopened.hash, submission.hash);
    }
    #[test]
    fn account_revocation_preserves_other_accounts_and_standalone_proof_permission() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("account-revocation.sqlite");
        let mut ring = Keyring::create(&path, PASSWORD).unwrap();
        let from = ring.import_public("First", &[31; 32]).unwrap();
        let to = ring.import_public("Second", &[32; 32]).unwrap();
        let app = Principal::Module {
            name: "account_revocation_fixture".into(),
            instance: String::new(),
        };
        ring.set_provider_grant(
            app.clone(),
            Grant {
                accounts: [*from.value(), *to.value()].into_iter().collect(),
                scopes: [Scope::Accounts, Scope::Transactions, Scope::CollectionProof]
                    .into_iter()
                    .collect(),
            },
        )
        .unwrap();
        let mut provider = Provider::unlocked(ring).unwrap();
        let state = lee::Account {
            balance: 100,
            program_owner: programs::authenticated_transfer().id(),
            ..Default::default()
        };
        let wallet = NativeWallet {
            endpoint: "http://fixture-node.invalid".into(),
            node: Memory {
                path: path.clone(),
                accounts: BTreeMap::from([(from, state.clone()), (to, state)]),
                reads: Cell::new(0),
                submitted: RefCell::new(vec![]),
                lose_response: Cell::new(false),
            },
        };
        let first = provider
            .propose_transaction(&app, &wallet, proposal(from, to, "3"), 1)
            .unwrap();
        let second = provider
            .propose_transaction(&app, &wallet, proposal(to, from, "4"), 1)
            .unwrap();
        let stale = Provider::unlocked(Keyring::open(&path, PASSWORD).unwrap()).unwrap();
        provider.revoke_account(&app, *from.value()).unwrap();
        assert!(provider.transaction_status(&app, &first, 2).is_err());
        assert!(provider.transaction_status(&app, &second, 2).is_ok());
        assert_eq!(
            provider
                .accounts(&app)
                .unwrap()
                .iter()
                .map(|info| info.account)
                .collect::<Vec<_>>(),
            vec![to]
        );
        assert!(
            !provider
                .permitted(&app, Scope::Transactions, Some(*from.value()))
                .unwrap()
        );
        assert!(
            provider
                .permitted(&app, Scope::Transactions, Some(*to.value()))
                .unwrap()
        );
        assert!(stale.accounts(&app).is_err());
        provider.revoke_account(&app, *to.value()).unwrap();
        assert!(provider.transaction_status(&app, &second, 3).is_err());
        assert!(provider.accounts(&app).is_err());
        assert!(
            provider
                .permitted(&app, Scope::CollectionProof, None)
                .unwrap()
        );
        assert!(!provider.permitted(&app, Scope::Transactions, None).unwrap());
        assert!(wallet.node.submitted.borrow().is_empty());
        drop(provider);
        let restored = Provider::unlocked(Keyring::open(&path, PASSWORD).unwrap()).unwrap();
        assert!(restored.accounts(&app).is_err());
        assert!(
            restored
                .permitted(&app, Scope::CollectionProof, None)
                .unwrap()
        );
        assert!(restored.grants()[0].grant.accounts.is_empty());
        assert_eq!(
            restored.grants()[0].grant.scopes,
            BTreeSet::from([Scope::CollectionProof])
        );
    }
    #[test]
    fn proposals_need_trusted_review_and_durable_outbox_survives_uncertainty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let mut ring = Keyring::create(&path, PASSWORD).unwrap();
        let from = ring.import_public("Signer", &[1; 32]).unwrap();
        let to = lee::AccountId::new([9; 32]);
        let app = Principal::Module {
            name: "transfer_app".into(),
            instance: String::new(),
        };
        let other = Principal::Module {
            name: "other_app".into(),
            instance: String::new(),
        };
        ring.set_provider_grant(
            app.clone(),
            Grant {
                accounts: BTreeSet::from([*from.value()]),
                scopes: BTreeSet::from([Scope::Transactions]),
            },
        )
        .unwrap();
        let mut provider = Provider::unlocked(ring).unwrap();
        let account = lee::Account {
            balance: 100,
            program_owner: programs::authenticated_transfer().id(),
            ..Default::default()
        };
        let wallet = NativeWallet {
            endpoint: "http://fixture-node.invalid".into(),
            node: Memory {
                path: path.clone(),
                accounts: BTreeMap::from([(from, account.clone()), (to, account)]),
                reads: Cell::new(0),
                submitted: RefCell::new(vec![]),
                lose_response: Cell::new(true),
            },
        };
        assert!(
            provider
                .propose_transaction(&other, &wallet, proposal(from, to, "5"), 10)
                .is_err()
        );
        assert!(
            provider
                .propose_transaction(&app, &wallet, proposal(from, to, "1.5"), 10)
                .is_err()
        );
        assert_eq!(wallet.node.reads.get(), 0);
        let denied = provider
            .propose_transaction(&app, &wallet, proposal(from, to, "5"), 10)
            .unwrap();
        assert!(provider.transaction_status(&other, &denied, 11).is_err());
        assert!(matches!(
            provider.transaction_status(&app, &denied, 11).unwrap(),
            TransactionState::Pending
        ));
        let prompts = provider.transaction_prompts(11);
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].principal, app);
        assert_eq!(
            prompts[0].source_verification.state,
            logos_registry_sdk::verification::SourceState::NotChecked
        );
        let Request::Transaction(tx) = &prompts[0].approval.request else {
            panic!()
        };
        assert_eq!(
            tx.effects,
            vec![logos_wallet_policy::Effect::NativeTransfer {
                amount: "5".into(),
                destination: *to.value()
            }]
        );
        assert!(wallet.node.submitted.borrow().is_empty());
        for method in ["approve", "decide_transaction", "sign_approved", "execute"] {
            let body = serde_json::json!({"method":method,"id":denied}).to_string();
            assert!(matches!(
                provider.dispatch(&app, &body, 11),
                Err(Error::InvalidRequest)
            ));
        }
        assert!(matches!(
            provider
                .decide_transaction(&denied, false, &wallet, 11)
                .unwrap(),
            TransactionState::Rejected
        ));
        assert!(
            provider
                .decide_transaction(&denied, true, &wallet, 12)
                .is_err()
        );
        assert!(provider.keyring.public_outbox().is_empty());
        let id = provider
            .propose_transaction(&app, &wallet, proposal(from, to, "6"), 20)
            .unwrap();
        let TransactionState::Submission { submission } =
            provider.decide_transaction(&id, true, &wallet, 21).unwrap()
        else {
            panic!()
        };
        assert_eq!(submission.state, SubmissionState::Uncertain);
        assert_eq!(wallet.node.submitted.borrow().len(), 1);
        assert!(provider.decide_transaction(&id, true, &wallet, 22).is_err());
        drop(provider);
        let mut provider = Provider::unlocked(Keyring::open(&path, PASSWORD).unwrap()).unwrap();
        let TransactionState::Submission {
            submission: recovered,
        } = provider.transaction_status(&app, &id, 1000).unwrap()
        else {
            panic!()
        };
        assert_eq!(recovered.hash, submission.hash);
        assert_eq!(recovered.state, SubmissionState::Uncertain);
        assert!(provider.transaction_status(&other, &id, 1000).is_err());
        assert_eq!(wallet.node.submitted.borrow().len(), 1); // no automatic replay
        wallet.node.lose_response.set(false);
        let acknowledged = provider
            .propose_transaction(&app, &wallet, proposal(from, to, "7"), 1000)
            .unwrap();
        let TransactionState::Submission { submission } = provider
            .decide_transaction(&acknowledged, true, &wallet, 1001)
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(submission.state, SubmissionState::Submitted);
        let expired = provider
            .propose_transaction(&app, &wallet, proposal(from, to, "8"), 1010)
            .unwrap();
        assert!(
            provider
                .decide_transaction(&expired, true, &wallet, 1310)
                .is_err()
        );
        let revoked = provider
            .propose_transaction(&app, &wallet, proposal(from, to, "8"), 1320)
            .unwrap();
        provider.revoke_scope(&app, Scope::Transactions).unwrap();
        assert!(
            provider
                .decide_transaction(&revoked, true, &wallet, 1321)
                .is_err()
        );
        assert_eq!(wallet.node.submitted.borrow().len(), 2);
    }
    #[test]
    fn changed_registry_record_requires_a_fresh_approval_without_signing() {
        use logos_registry_sdk::verification::{ReviewConfig, SourceState};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let mut ring = Keyring::create(&path, PASSWORD).unwrap();
        let from = ring.import_public("Signer", &[1; 32]).unwrap();
        let to = lee::AccountId::new([9; 32]);
        let app = Principal::Module {
            name: "source_review_app".into(),
            instance: String::new(),
        };
        ring.set_provider_grant(
            app.clone(),
            Grant {
                accounts: BTreeSet::from([*from.value()]),
                scopes: BTreeSet::from([Scope::Transactions]),
            },
        )
        .unwrap();
        let mut provider = Provider::unlocked(ring).unwrap();
        let account = lee::Account {
            balance: 100,
            program_owner: programs::authenticated_transfer().id(),
            ..Default::default()
        };
        let mut wallet = NativeWallet {
            endpoint: "http://fixture.invalid".into(),
            node: Memory {
                path,
                accounts: BTreeMap::from([(from, account.clone()), (to, account)]),
                reads: Cell::new(0),
                submitted: RefCell::new(vec![]),
                lose_response: Cell::new(false),
            },
        };
        let registry = [7; 8];
        let program = logos_registry_sdk::program_bytes(&programs::authenticated_transfer().id());
        let author = [4; 32];
        let mut entry = logos_prize_registry::Entry {
            schema: 1,
            program_id: program,
            registrant: author,
            ordinal: 0,
            revision: 0,
            submitted_at: 1,
            metadata: logos_prize_registry::Metadata {
                name: "Unverified registration fixture".into(),
                version: "1".into(),
                author: "Fixture".into(),
                description: "Not a source rebuild".into(),
                tags: vec![],
                idl_cid: "bafyFixtureIDL".into(),
                source_cid: "bafyFixtureSource".into(),
                source_commit: "a".repeat(40),
                build_config_cid: "bafyFixtureBuild".into(),
            },
        };
        let address = logos_registry_sdk::entry_address(&registry, &program, &author);
        let stored = |entry: &logos_prize_registry::Entry| lee::Account {
            program_owner: registry,
            data: borsh::to_vec(entry).unwrap().try_into().unwrap(),
            ..Default::default()
        };
        wallet.node.accounts.insert(address, stored(&entry));
        let registry_hex: String = logos_registry_sdk::program_bytes(&registry)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        provider.configure_source_review(Some(
            ReviewConfig::new(
                &registry_hex,
                dir.path().join("receipts"),
                BTreeMap::from([(program, author)]),
            )
            .unwrap(),
        ));
        let id = provider
            .propose_transaction(&app, &wallet, proposal(from, to, "5"), 10)
            .unwrap();
        let prompts = provider.transaction_prompts(11);
        assert!(matches!(
            prompts[0].source_verification.state,
            SourceState::Registered {
                revision: 0,
                local_rebuild: None,
                ..
            }
        ));
        entry.revision = 1;
        wallet.node.accounts.insert(address, stored(&entry));
        assert!(matches!(
            provider.decide_transaction(&id, true, &wallet, 11),
            Err(Error::SourceChanged)
        ));
        assert!(provider.decide_transaction(&id, true, &wallet, 12).is_err());
        assert!(wallet.node.submitted.borrow().is_empty());
        assert!(provider.keyring.public_outbox().is_empty());
        let id = provider
            .propose_transaction(&app, &wallet, proposal(from, to, "5"), 20)
            .unwrap();
        wallet.node.accounts.remove(&address);
        assert!(matches!(
            provider.decide_transaction(&id, true, &wallet, 21),
            Err(Error::SourceChanged)
        ));
        let id = provider
            .propose_transaction(&app, &wallet, proposal(from, to, "5"), 30)
            .unwrap();
        assert_eq!(
            provider.transaction_prompts(31)[0]
                .source_verification
                .state,
            SourceState::Unavailable
        );
        provider.configure_source_review(None);
        assert!(provider.decide_transaction(&id, true, &wallet, 31).is_err());
        assert!(wallet.node.submitted.borrow().is_empty());
        assert!(provider.keyring.public_outbox().is_empty());
        assert!(
            provider
                .dispatch(
                    &app,
                    r#"{"method":"configure_source_review","registry":"forged"}"#,
                    31
                )
                .is_err()
        );
    }
    #[test]
    fn owner_actions_require_review_without_granting_or_canceling_other_apps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let mut ring = Keyring::create(&path, PASSWORD).unwrap();
        let from = ring.import_public("Owner", &[1; 32]).unwrap();
        let private = ring.generate_private("Private").unwrap();
        let to = lee::AccountId::new([9; 32]);
        let app = Principal::Module {
            name: "existing_app".into(),
            instance: String::new(),
        };
        let owner = Principal::Module {
            name: super::super::native::OWNER_MODULE.into(),
            instance: String::new(),
        };
        ring.set_provider_grant(
            app.clone(),
            Grant {
                accounts: BTreeSet::from([*from.value()]),
                scopes: BTreeSet::from([Scope::Transactions]),
            },
        )
        .unwrap();
        let mut provider = Provider::unlocked(ring).unwrap();
        let state = lee::Account {
            balance: 100,
            program_owner: programs::authenticated_transfer().id(),
            ..Default::default()
        };
        let wallet = NativeWallet {
            endpoint: "http://fixture.invalid".into(),
            node: Memory {
                path,
                accounts: BTreeMap::from([(from, state.clone()), (to, state)]),
                reads: Cell::new(0),
                submitted: RefCell::new(vec![]),
                lose_response: Cell::new(false),
            },
        };
        assert!(
            provider
                .propose_owner_transaction(&wallet, proposal(private, to, "1"), 1)
                .is_err()
        );
        assert!(
            provider
                .propose_owner_transaction(&wallet, proposal(to, from, "1"), 1)
                .is_err()
        );
        assert_eq!(wallet.node.reads.get(), 0);
        let normal = provider
            .propose_transaction(&app, &wallet, proposal(from, to, "3"), 2)
            .unwrap();
        let canceled = provider
            .propose_owner_transaction(&wallet, proposal(from, to, "4"), 2)
            .unwrap();
        assert!(
            !provider
                .permitted(&owner, Scope::Transactions, Some(*from.value()))
                .unwrap()
        );
        assert_eq!(provider.grants().len(), 1);
        assert!(
            provider
                .propose_transaction(&owner, &wallet, proposal(from, to, "4"), 2)
                .is_err()
        );
        assert!(wallet.node.submitted.borrow().is_empty());
        // Both isolated policies use numeric approval 1. Canceling the owner
        // record must not accidentally cancel the ordinary app's approval 1.
        provider.cancel_transactions(Some(&owner));
        assert!(
            provider
                .decide_transaction(&canceled, true, &wallet, 3)
                .is_err()
        );
        assert!(matches!(
            provider
                .decide_transaction(&normal, true, &wallet, 3)
                .unwrap(),
            TransactionState::Submission { .. }
        ));
        let own = provider
            .propose_owner_transaction(&wallet, proposal(from, to, "5"), 4)
            .unwrap();
        assert_eq!(wallet.node.submitted.borrow().len(), 1);
        assert!(provider.transaction_status(&app, &own, 4).is_err());
        assert!(matches!(
            provider.decide_transaction(&own, true, &wallet, 5).unwrap(),
            TransactionState::Submission { .. }
        ));
        assert!(provider.decide_transaction(&own, true, &wallet, 6).is_err());
        assert_eq!(wallet.node.submitted.borrow().len(), 2);
        assert!(
            !provider
                .permitted(&owner, Scope::Transactions, Some(*from.value()))
                .unwrap()
        );
        assert_eq!(provider.grants().len(), 1);
        assert_eq!(provider.grants()[0].principal, app);
    }
}
