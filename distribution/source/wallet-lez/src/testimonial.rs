// SPDX-License-Identifier: MIT OR Apache-2.0
//! Wallet-built testimonial messages. The deployed image must match this reviewed guest.
use super::*;
use logos_testimonial::{Catalog, Content, Instruction, PAGE_SIZE, Page, SCHEMA};
use spel_framework::prelude::{ToSeed, compute_pda, seed_from_str};
pub const PROGRAM_HEX: &str = "a9fc05bec2f9f202c89311d69f4181233f7560171c80ba3ee92b11da9aa0b692";
pub enum Action {
    Initialize,
    CreatePage { number: u64 },
    Publish(Content),
}
fn decode<T: borsh::BorshDeserialize>(state: lee::Account, program: [u32; 8]) -> Result<T> {
    if state.program_owner != program {
        return Err(Error::Invalid(
            "Testimonial registry is missing or has the wrong owner",
        ));
    }
    borsh::from_slice(&Vec::<u8>::from(state.data))
        .map_err(|_| Error::Invalid("Invalid testimonial registry state"))
}
impl<N: Node> NativeWallet<N> {
    pub fn prepare_testimonial(
        &self,
        policy: &mut Policy,
        app: &AppId,
        author: [u8; 32],
        action: Action,
        now: u64,
    ) -> Result<PreparedTransfer> {
        if !policy.permitted(app, Scope::Transactions, Some(author)) {
            return Err(Error::Invalid("Transaction permission denied"));
        }
        if let Action::Publish(content) = &action {
            content
                .validate()
                .map_err(|_| Error::Invalid("Invalid testimonial content"))?;
        }
        let program = logos_registry_sdk::parse_program(PROGRAM_HEX)?;
        let author_id = AccountId::new(author);
        let state = self.node.account(author_id)?;
        if state.program_owner != programs::authenticated_transfer().id() {
            return Err(Error::Invalid(
                "Select an initialized public native account to publish",
            ));
        }
        let catalog_id = compute_pda(&program, &[&seed_from_str("testimonials")]);
        let catalog_state = self.node.account(catalog_id)?;
        let (accounts, instruction, title, explanation, text) = match action {
            Action::Initialize => {
                if catalog_state != lee::Account::default() {
                    return Err(Error::Invalid(
                        "Testimonial registry is already initialized",
                    ));
                }
                (vec![catalog_id,author_id],Instruction::Initialize{},"Initialize testimonial registry","Create the public testimonial catalog. No testimonial is published and no assets are transferred.".to_owned(),None)
            }
            Action::CreatePage { number } => {
                let catalog: Catalog = decode(catalog_state, program)?;
                if catalog.schema != SCHEMA || number != catalog.count / PAGE_SIZE as u64 {
                    return Err(Error::Invalid(
                        "Refresh the testimonial catalog before creating its current page",
                    ));
                }
                let page = compute_pda(
                    &program,
                    &[&seed_from_str("testimonial-page"), &number.to_seed()],
                );
                if self.node.account(page)? != lee::Account::default() {
                    return Err(Error::Invalid("Testimonial page already exists"));
                }
                (
                    vec![page, author_id],
                    Instruction::CreatePage { number },
                    "Create testimonial index page",
                    format!(
                        "Create public index page {number}. No testimonial is published and no assets are transferred."
                    ),
                    None,
                )
            }
            Action::Publish(content) => {
                let catalog: Catalog = decode(catalog_state, program)?;
                if catalog.schema != SCHEMA {
                    return Err(Error::Invalid("Unsupported testimonial catalog"));
                }
                let ordinal = catalog.count;
                let number = ordinal / PAGE_SIZE as u64;
                let page_id = compute_pda(
                    &program,
                    &[&seed_from_str("testimonial-page"), &number.to_seed()],
                );
                let page: Page = decode(self.node.account(page_id)?, program)?;
                if page.schema != SCHEMA
                    || page.number != number
                    || page.entries.len() != (ordinal % PAGE_SIZE as u64) as usize
                {
                    return Err(Error::Invalid(
                        "Testimonial page is inconsistent; refresh before retrying",
                    ));
                }
                let entry = compute_pda(
                    &program,
                    &[&seed_from_str("testimonial"), &ordinal.to_seed()],
                );
                if self.node.account(entry)? != lee::Account::default() {
                    return Err(Error::Invalid("Testimonial ordinal is already occupied"));
                }
                let timestamp = now
                    .checked_mul(1000)
                    .ok_or(Error::Invalid("Timestamp overflow"))?;
                let instruction = Instruction::Publish {
                    page_number: number,
                    ordinal,
                    submitted_at: timestamp,
                    content_json: serde_json::to_string(&content)
                        .map_err(|_| Error::Invalid("Cannot encode testimonial"))?,
                };
                let explanation = format!(
                    "Publish a permanent public testimonial from {author_id}. Submission: {}. Username: {}. The exact text below is public and cannot be edited or deleted. No assets or allowances are transferred.",
                    content.submission_id,
                    if content.username.is_empty() {
                        "(none)"
                    } else {
                        &content.username
                    }
                );
                (
                    vec![catalog_id, page_id, entry, author_id],
                    instruction,
                    "Publish testimonial",
                    explanation,
                    Some(content.text),
                )
            }
        };
        let message = Message::try_new(program, accounts, vec![state.nonce], instruction)
            .map_err(|_| Error::Invalid("Cannot encode testimonial transaction"))?;
        let mut effects = vec![Effect::ContractCall {
            program: logos_registry_sdk::program_bytes(&program),
            instruction: title.into(),
            explanation,
        }];
        if let Some(text) = text {
            effects.push(Effect::ContractCall {
                program: logos_registry_sdk::program_bytes(&program),
                instruction: "Text published on-chain".into(),
                explanation: text,
            });
        }
        self.prepare_message(policy, app, author, message, effects, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logos_wallet_policy::Grant;
    use std::collections::{BTreeMap, BTreeSet};
    struct Memory {
        accounts: BTreeMap<AccountId, lee::Account>,
        forbid_reads: bool,
    }
    impl AccountReader for Memory {
        fn account(&self, id: AccountId) -> logos_registry_sdk::Result<lee::Account> {
            assert!(!self.forbid_reads, "Unauthorized network read");
            Ok(self.accounts.get(&id).cloned().unwrap_or_default())
        }
    }
    impl Node for Memory {
        fn submit_transaction(&self, _: &LeeTransaction) -> logos_registry_sdk::Result<HashType> {
            panic!("No automatic submission")
        }
    }
    fn fixture() -> (NativeWallet<Memory>, Policy, AppId, PrivateKey, [u8; 32]) {
        let program = logos_registry_sdk::parse_program(PROGRAM_HEX).unwrap();
        let key = PrivateKey::try_new([4; 32]).unwrap();
        let author = *AccountId::from(&PublicKey::new_from_private_key(&key)).value();
        let mut accounts = BTreeMap::new();
        accounts.insert(
            AccountId::new(author),
            lee::Account {
                program_owner: programs::authenticated_transfer().id(),
                ..Default::default()
            },
        );
        let mut store = |id, state: Vec<u8>| {
            accounts.insert(
                id,
                lee::Account {
                    program_owner: program,
                    data: state.try_into().unwrap(),
                    ..Default::default()
                },
            );
        };
        store(
            compute_pda(&program, &[&seed_from_str("testimonials")]),
            borsh::to_vec(&Catalog {
                schema: SCHEMA,
                count: 0,
            })
            .unwrap(),
        );
        store(
            compute_pda(
                &program,
                &[&seed_from_str("testimonial-page"), &0u64.to_seed()],
            ),
            borsh::to_vec(&Page {
                schema: SCHEMA,
                number: 0,
                entries: vec![],
            })
            .unwrap(),
        );
        let app = AppId("testimonial_test".into());
        let mut policy = Policy::default();
        policy
            .set_grant(
                app.clone(),
                Grant {
                    accounts: BTreeSet::from([author]),
                    scopes: BTreeSet::from([Scope::Transactions]),
                },
            )
            .unwrap();
        (
            NativeWallet {
                node: Memory {
                    accounts,
                    forbid_reads: false,
                },
                endpoint: "http://127.0.0.1:1".into(),
            },
            policy,
            app,
            key,
            author,
        )
    }
    fn content() -> Content {
        Content {
            submission_id: "LP-0021-fixture".into(),
            username: String::new(),
            text: "x".repeat(4096),
        }
    }
    #[test]
    fn exact_maximum_text_is_reviewed_and_approval_is_one_time() {
        let (wallet, mut policy, app, key, author) = fixture();
        let prepared = wallet
            .prepare_testimonial(&mut policy, &app, author, Action::Publish(content()), 10)
            .unwrap();
        assert_eq!(
            prepared.message.program_id,
            logos_registry_sdk::parse_program(PROGRAM_HEX).unwrap()
        );
        let Request::Transaction(review) = &prepared.prompt.request else {
            panic!()
        };
        assert!(
            matches!(&review.effects[0],Effect::ContractCall{explanation,..} if explanation.contains("permanent public") && explanation.contains("LP-0021-fixture"))
        );
        assert!(
            matches!(&review.effects[1],Effect::ContractCall{explanation,..} if *explanation==content().text)
        );
        assert!(
            wallet
                .sign_approved(&mut policy, &app, &prepared, &key, 11)
                .is_err()
        );
        policy.decide(prepared.prompt.id, true, 11).unwrap();
        assert!(
            wallet
                .sign_approved(&mut policy, &app, &prepared, &key, 12)
                .is_ok()
        );
        assert!(
            wallet
                .sign_approved(&mut policy, &app, &prepared, &key, 13)
                .is_err()
        );
    }
    #[test]
    fn permission_and_content_rejected_before_reads() {
        let (mut wallet, mut policy, app, _, author) = fixture();
        wallet.node.forbid_reads = true;
        let mut denied = Policy::default();
        assert!(
            wallet
                .prepare_testimonial(&mut denied, &app, author, Action::Initialize, 10)
                .is_err()
        );
        let mut bad = content();
        bad.text.clear();
        assert!(
            wallet
                .prepare_testimonial(&mut policy, &app, author, Action::Publish(bad), 10)
                .is_err()
        );
    }
    #[test]
    fn rejects_forged_registry_and_occupied_entry() {
        let (mut wallet, mut policy, app, _, author) = fixture();
        let program = logos_registry_sdk::parse_program(PROGRAM_HEX).unwrap();
        let entry = compute_pda(&program, &[&seed_from_str("testimonial"), &0u64.to_seed()]);
        wallet.node.accounts.insert(
            entry,
            lee::Account {
                balance: 1,
                ..Default::default()
            },
        );
        assert!(
            wallet
                .prepare_testimonial(&mut policy, &app, author, Action::Publish(content()), 10)
                .is_err()
        );
        wallet.node.accounts.remove(&entry);
        let catalog = compute_pda(&program, &[&seed_from_str("testimonials")]);
        wallet
            .node
            .accounts
            .get_mut(&catalog)
            .unwrap()
            .program_owner = [9; 8];
        assert!(
            wallet
                .prepare_testimonial(&mut policy, &app, author, Action::Publish(content()), 10)
                .is_err()
        );
    }
}
