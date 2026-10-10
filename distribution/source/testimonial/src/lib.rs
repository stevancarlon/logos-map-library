// SPDX-License-Identifier: MIT OR Apache-2.0
//! Public, immutable LEZ testimonials. Signed authorship is not proof of genuine adoption.
use serde::{Deserialize, Serialize};
use spel_framework::prelude::*;
pub const PAGE_SIZE: usize = 128;
pub const SCHEMA: u16 = 1;
#[account_type]
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Content {
    pub submission_id: String,
    /// Empty means no username; the signing account remains public.
    pub username: String,
    pub text: String,
}
impl Content {
    pub fn validate(&self) -> Result<(), SpelError> {
        if self.submission_id.is_empty()
            || self.submission_id.len() > 96
            || !self
                .submission_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
        {
            return Err(SpelError::custom(1, "Invalid submission identifier"));
        }
        if self.username.len() > 80
            || self.username.chars().any(char::is_control)
            || (!self.username.is_empty() && self.username.trim().is_empty())
        {
            return Err(SpelError::custom(2, "Invalid optional username"));
        }
        if self.text.trim().is_empty()
            || self.text.len() > 4096
            || self.text.chars().any(|c| c.is_control() && c != '\n')
        {
            return Err(SpelError::custom(
                3,
                "Testimonial text must contain 1–4096 UTF-8 bytes",
            ));
        }
        Ok(())
    }
}
#[account_type]
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct Catalog {
    pub schema: u16,
    pub count: u64,
}
#[account_type]
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct Page {
    pub schema: u16,
    pub number: u64,
    pub entries: Vec<[u8; 32]>,
}
#[account_type]
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize, PartialEq)]
pub struct Testimonial {
    pub schema: u16,
    pub ordinal: u64,
    pub author: [u8; 32],
    pub submitted_at: u64,
    pub content: Content,
}
fn decode<T: BorshDeserialize>(account: &AccountWithMetadata) -> Result<T, SpelError> {
    borsh::from_slice(&Vec::<u8>::from(account.account.data.clone()))
        .map_err(|_| SpelError::custom(4, "Invalid account state"))
}
fn encode<T: BorshSerialize>(
    account: &mut AccountWithMetadata,
    state: &T,
) -> Result<(), SpelError> {
    account.account.data = borsh::to_vec(state)
        .map_err(|_| SpelError::custom(5, "Encoding failed"))?
        .try_into()
        .map_err(|_| SpelError::custom(6, "Account state too large"))?;
    Ok(())
}
#[lez_program]
pub mod testimonials {
    #[allow(unused_imports)]
    use super::*;
    #[instruction]
    pub fn initialize(
        #[account(init,pda=literal("testimonials"))] mut catalog: AccountWithMetadata,
        #[account(signer)] payer: AccountWithMetadata,
    ) -> SpelResult {
        encode(
            &mut catalog,
            &Catalog {
                schema: SCHEMA,
                count: 0,
            },
        )?;
        Ok(SpelOutput::execute(vec![catalog, payer], vec![]))
    }
    #[instruction]
    pub fn create_page(
        #[account(init,pda=[literal("testimonial-page"),arg("number")])]
        mut page: AccountWithMetadata,
        #[account(signer)] payer: AccountWithMetadata,
        number: u64,
    ) -> SpelResult {
        encode(
            &mut page,
            &Page {
                schema: SCHEMA,
                number,
                entries: vec![],
            },
        )?;
        Ok(SpelOutput::execute(vec![page, payer], vec![]))
    }
    #[instruction]
    #[allow(clippy::too_many_arguments)]
    pub fn publish(
        #[account(mut,owner=self_program_id,pda=literal("testimonials"))]
        mut catalog: AccountWithMetadata,
        #[account(mut,owner=self_program_id,pda=[literal("testimonial-page"),arg("page_number")])]
        mut page: AccountWithMetadata,
        #[account(init,pda=[literal("testimonial"),arg("ordinal")])] mut entry: AccountWithMetadata,
        #[account(signer)] author: AccountWithMetadata,
        page_number: u64,
        ordinal: u64,
        submitted_at: u64,
        content_json: String,
    ) -> SpelResult {
        if content_json.len() > 32768 {
            return Err(SpelError::custom(7, "Content encoding too large"));
        }
        let content: Content = serde_json::from_str(&content_json)
            .map_err(|_| SpelError::custom(8, "Invalid content"))?;
        content.validate()?;
        let mut index: Catalog = decode(&catalog)?;
        let mut entries: Page = decode(&page)?;
        if index.schema != SCHEMA
            || entries.schema != SCHEMA
            || ordinal != index.count
            || page_number != ordinal / PAGE_SIZE as u64
            || entries.number != page_number
            || entries.entries.len() != (ordinal % PAGE_SIZE as u64) as usize
        {
            return Err(SpelError::custom(
                9,
                "Stale or invalid catalog page; refresh before publishing",
            ));
        }
        let state = Testimonial {
            schema: SCHEMA,
            ordinal,
            author: *author.account_id.value(),
            submitted_at,
            content,
        };
        index.count = index
            .count
            .checked_add(1)
            .ok_or_else(|| SpelError::custom(10, "Catalog full"))?;
        entries.entries.push(*entry.account_id.value());
        encode(&mut catalog, &index)?;
        encode(&mut page, &entries)?;
        encode(&mut entry, &state)?;
        let end = submitted_at
            .checked_add(300_001)
            .ok_or_else(|| SpelError::custom(11, "Timestamp overflow"))?;
        SpelOutput::execute(vec![catalog, page, entry, author], vec![])
            .try_with_timestamp_validity_window(submitted_at.saturating_sub(300_000)..end)
            .map_err(|e| SpelError::custom(12, e.to_string()))
    }
}
