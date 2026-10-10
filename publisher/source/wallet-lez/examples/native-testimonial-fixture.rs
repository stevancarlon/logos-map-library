// SPDX-License-Identifier: MIT OR Apache-2.0
//! Disposable setup/inspection for a real Basecamp testimonial consumer.
use common::transaction::LeeTransaction;
use lee::{
    AccountId, PrivateKey, PublicKey, PublicTransaction,
    public_transaction::{Message, WitnessSet},
};
use logos_registry_sdk::{AccountReader, HttpNode};
use logos_testimonial::{Catalog, Instruction, Testimonial};
use logos_wallet_lez::keyring::Keyring;
use serde_json::json;
use spel_framework::prelude::{ToSeed, compute_pda, seed_from_str};
use std::{path::Path, time::Duration};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn included(node: &HttpNode, tx: LeeTransaction) -> Result<common::HashType> {
    let hash = node.submit(&tx)?;
    for _ in 0..120 {
        if node.confirmed(hash)? {
            return Ok(hash);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err("Testimonial fixture transaction was not included".into())
}
fn signed(
    node: &HttpNode,
    program: [u32; 8],
    key: &PrivateKey,
    accounts: Vec<AccountId>,
    instruction: Instruction,
) -> Result<LeeTransaction> {
    let author = AccountId::from(&PublicKey::new_from_private_key(key));
    let message = Message::try_new(
        program,
        accounts,
        vec![node.account(author)?.nonce],
        instruction,
    )?;
    let witness = WitnessSet::for_message(&message, &[key]);
    Ok(LeeTransaction::Public(PublicTransaction::new(
        message, witness,
    )))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        return Err("RPC BINARY seed|inspect WALLET_PATH required".into());
    }
    args[1]
        .strip_prefix("http://127.0.0.1:")
        .ok_or("Disposable loopback only")?
        .parse::<u16>()?;
    let node = HttpNode::new(&args[1])?;
    let program = logos_registry_sdk::parse_program(logos_wallet_lez::testimonial::PROGRAM_HEX)?;
    let catalog = compute_pda(&program, &[&seed_from_str("testimonials")]);
    let page = compute_pda(
        &program,
        &[&seed_from_str("testimonial-page"), &0u64.to_seed()],
    );
    let entry = compute_pda(&program, &[&seed_from_str("testimonial"), &0u64.to_seed()]);
    if args[3] == "seed" {
        let binary = std::fs::read(&args[2])?;
        assert_eq!(risc0_binfmt::compute_image_id(&binary)?.as_words(), program);
        included(
            &node,
            LeeTransaction::ProgramDeployment(lee::ProgramDeploymentTransaction::new(
                lee::program_deployment_transaction::Message::new(binary),
            )),
        )?;
        let key = PrivateKey::try_new([1; 32])?;
        let author = AccountId::from(&PublicKey::new_from_private_key(&key));
        included(
            &node,
            signed(
                &node,
                program,
                &key,
                vec![catalog, author],
                Instruction::Initialize {},
            )?,
        )?;
        included(
            &node,
            signed(
                &node,
                program,
                &key,
                vec![page, author],
                Instruction::CreatePage { number: 0 },
            )?,
        )?;
        let path = Path::new(&args[4]);
        std::fs::create_dir_all(path.parent().ok_or("Wallet parent missing")?)?;
        let mut ring = Keyring::create(path, b"disposable testimonial password")?;
        ring.import_public("Synthetic testimonial account", &[1; 32])?;
        println!(
            "{}",
            json!({"author":author,"program":logos_wallet_lez::testimonial::PROGRAM_HEX})
        );
    } else if args[3] == "inspect" {
        let state = node.account(catalog)?;
        assert_eq!(state.program_owner, program);
        let index: Catalog = borsh::from_slice(&Vec::<u8>::from(state.data))?;
        assert_eq!(index.count, 1);
        let state = node.account(entry)?;
        assert_eq!(state.program_owner, program);
        let value: Testimonial = borsh::from_slice(&Vec::<u8>::from(state.data))?;
        println!("{}", serde_json::to_value(value)?);
    } else {
        return Err("Unknown fixture action".into());
    }
    Ok(())
}
