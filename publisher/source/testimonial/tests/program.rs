// SPDX-License-Identifier: MIT OR Apache-2.0
use logos_testimonial::{Catalog, Content, Page, SCHEMA, Testimonial, testimonials::*};
use spel_framework::prelude::*;
const PROGRAM: [u32; 8] = [17; 8];
fn account(id: AccountId, signed: bool) -> AccountWithMetadata {
    AccountWithMetadata {
        account_id: id,
        account: Account::default(),
        is_authorized: signed,
    }
}
fn stored<T: BorshSerialize>(id: AccountId, value: T) -> AccountWithMetadata {
    let mut a = account(id, false);
    a.account.program_owner = PROGRAM;
    a.account.data = borsh::to_vec(&value).unwrap().try_into().unwrap();
    a
}
fn inputs() -> Vec<AccountWithMetadata> {
    vec![
        stored(
            compute_pda(&PROGRAM, &[&seed_from_str("testimonials")]),
            Catalog {
                schema: SCHEMA,
                count: 0,
            },
        ),
        stored(
            compute_pda(
                &PROGRAM,
                &[&seed_from_str("testimonial-page"), &0u64.to_seed()],
            ),
            Page {
                schema: SCHEMA,
                number: 0,
                entries: vec![],
            },
        ),
        account(
            compute_pda(&PROGRAM, &[&seed_from_str("testimonial"), &0u64.to_seed()]),
            false,
        ),
        account(AccountId::new([7; 32]), true),
    ]
}
fn content() -> Content {
    Content {
        submission_id: "LP-0021-disposable-fixture".into(),
        username: String::new(),
        text: "Synthetic test only.\nNot an adoption testimonial.".into(),
    }
}
fn run(accounts: Vec<AccountWithMetadata>, ordinal: u64, json: String) -> SpelResult {
    let [catalog, page, entry, author]: [_; 4] = accounts.try_into().unwrap();
    publish(catalog, page, entry, author, 0, ordinal, 100, json)
}
#[test]
fn publishes_immutable_signed_content_and_discovery_index() {
    let input = inputs();
    __validate_publish(&input, &PROGRAM, &vec![], &0, &0).unwrap();
    let output = run(input, 0, serde_json::to_string(&content()).unwrap()).unwrap();
    let value: Testimonial = borsh::from_slice(&Vec::<u8>::from(
        output.post_states[2].account().data.clone(),
    ))
    .unwrap();
    assert_eq!(value.author, [7; 32]);
    assert_eq!(value.content, content());
    assert_eq!(value.ordinal, 0);
    assert_eq!(output.timestamp_validity_window.start(), Some(0));
    assert_eq!(output.timestamp_validity_window.end(), Some(300_101));
    let page: Page = borsh::from_slice(&Vec::<u8>::from(
        output.post_states[1].account().data.clone(),
    ))
    .unwrap();
    assert_eq!(page.entries, vec![*inputs()[2].account_id.value()]);
    let mut duplicate = inputs();
    duplicate[2].account = output.post_states[2].account().clone();
    assert!(__validate_publish(&duplicate, &PROGRAM, &vec![], &0, &0).is_err());
}
#[test]
fn rejects_unsigned_author_forged_pdas_and_foreign_catalog() {
    let mut input = inputs();
    input[3].is_authorized = false;
    assert!(__validate_publish(&input, &PROGRAM, &vec![], &0, &0).is_err());
    let mut input = inputs();
    input[2].account_id = AccountId::new([9; 32]);
    assert!(__validate_publish(&input, &PROGRAM, &vec![], &0, &0).is_err());
    let mut input = inputs();
    input[0].account.program_owner = [9; 8];
    assert!(__validate_publish(&input, &PROGRAM, &vec![], &0, &0).is_err());
}
#[test]
fn rejects_stale_ordinal_and_inconsistent_page() {
    let json = serde_json::to_string(&content()).unwrap();
    assert!(run(inputs(), 1, json.clone()).is_err());
    let mut input = inputs();
    input[1].account.data = borsh::to_vec(&Page {
        schema: SCHEMA,
        number: 0,
        entries: vec![[9; 32]],
    })
    .unwrap()
    .try_into()
    .unwrap();
    assert!(run(input, 0, json).is_err());
}
#[test]
fn bounds_public_content_and_rejects_hidden_extra_fields() {
    let mut value = content();
    value.text = " ".into();
    assert!(value.validate().is_err());
    value.text = "x".repeat(4097);
    assert!(value.validate().is_err());
    value = content();
    value.username = "\n".into();
    assert!(value.validate().is_err());
    value = content();
    value.submission_id = "other/submission".into();
    assert!(value.validate().is_err());
    let mut value = serde_json::to_value(content()).unwrap();
    value["author"] = serde_json::json!("forged");
    assert!(run(inputs(), 0, value.to_string()).is_err());
}
