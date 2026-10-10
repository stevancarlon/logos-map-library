// SPDX-License-Identifier: MIT OR Apache-2.0
use logos_registry_sdk::publisher::Write;
use logos_registry_sdk::{HttpNode, Registry, parse_program, program_bytes, resolve, verify_image};
use logos_wallet_policy::vault;
use spel_framework::prelude::AccountId;
use std::path::Path;
use zeroize::Zeroizing;

fn bounded_file(path: &str, limit: u64) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err("File exceeds input limit".into());
    }
    Ok(bytes)
}
fn password(prompt: &str) -> Result<Zeroizing<String>, Box<dyn Error>> {
    Ok(Zeroizing::new(logos_registry_sdk::terminal::prompt_secret(
        prompt,
    )?))
}

use std::{error::Error, io::Read, str::FromStr};

fn run(args: Vec<String>) -> Result<(), Box<dyn Error>> {
    match args.get(1).map(String::as_str) {
        Some("package-image") if args.len() == 5 => {
            use std::io::Write as _;
            let user = bounded_file(&args[2], 32 * 1024 * 1024)?;
            let kernel = bounded_file(&args[3], 32 * 1024 * 1024)?;
            let bytes = risc0_binfmt::ProgramBinary::new(&user, &kernel).encode();
            let image = risc0_binfmt::compute_image_id(&bytes)?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&args[4])?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            println!(
                "{}",
                serde_json::json!({"program":image.to_string(),"artifact":args[4]})
            );
        }
        Some("verify-source") if args.len() == 10 => {
            let registry = Registry {
                reader: HttpNode::new(&args[2])?,
                program: parse_program(&args[3])?,
            };
            let entry = registry.lookup(
                &program_bytes(&parse_program(&args[4])?),
                AccountId::from_str(&args[5])?.value(),
            )?;
            let recipe: logos_registry_sdk::verification::BuildRecipe =
                serde_json::from_slice(&bounded_file(&args[8], 16384)?)?;
            eprintln!(
                "Running the explicitly selected build recipe locally: {}",
                serde_json::to_string(&recipe)?
            );
            let receipt = logos_registry_sdk::verification::rebuild(
                &args[2],
                &args[3],
                &entry,
                Path::new(&args[7]),
                &recipe,
                &HttpNode::new(&args[6])?,
            )?;
            // Re-read after the build so an update during compilation cannot be
            // displayed as verified against the current entry.
            let current = registry.lookup(&entry.program_id, &entry.registrant)?;
            if current != entry {
                return Err("Registry entry changed during rebuild; no receipt saved".into());
            }
            logos_registry_sdk::verification::save(Path::new(&args[9]), &receipt)?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        Some("source-status") if args.len() == 7 => {
            let registry = Registry {
                reader: HttpNode::new(&args[2])?,
                program: parse_program(&args[3])?,
            };
            let entry = registry.lookup(
                &program_bytes(&parse_program(&args[4])?),
                AccountId::from_str(&args[5])?.value(),
            )?;
            let receipt = logos_registry_sdk::verification::lookup(
                Path::new(&args[6]),
                &args[2],
                &args[3],
                &entry,
            )?;
            println!(
                "{}",
                serde_json::json!({"locally_verified":receipt.is_some(),"receipt":receipt})
            );
        }
        Some("build-recipe") if args.len() == 7 => {
            use logos_registry_sdk::StorageReader;
            let registry = Registry {
                reader: HttpNode::new(&args[2])?,
                program: parse_program(&args[3])?,
            };
            let entry = registry.lookup(
                &program_bytes(&parse_program(&args[4])?),
                AccountId::from_str(&args[5])?.value(),
            )?;
            let recipe: logos_registry_sdk::verification::BuildRecipe = serde_json::from_slice(
                &HttpNode::new(&args[6])?.read(&entry.metadata.build_config_cid, 16384)?,
            )?;
            recipe.validate()?;
            println!("{}", serde_json::to_string_pretty(&recipe)?);
        }
        Some("key-import") if args.len() == 3 => {
            let secret = password("LEZ private key (64 hex characters; input hidden): ")?;
            let mut bytes = Zeroizing::new([0u8; 32]);
            hex::decode_to_slice(secret.trim(), bytes.as_mut())?;
            let key = lee::PrivateKey::try_new(*bytes)?;
            let author = AccountId::from(&lee::PublicKey::new_from_private_key(&key));
            let pass = password("New vault password: ")?;
            let confirm = password("Repeat vault password: ")?;
            if *pass != *confirm {
                return Err("Passwords do not match".into());
            }
            let mut payload = Zeroizing::new(Vec::from(b"REGKEY01".as_slice()));
            payload.extend_from_slice(bytes.as_ref());
            vault::create_file(Path::new(&args[2]), pass.as_bytes(), &payload)?;
            println!("{}", serde_json::json!({"account":author,"vault":args[2]}));
        }
        Some("write") if args.len() == 6 => {
            let node = HttpNode::new(&args[2])?;
            let program = parse_program(&args[3])?;
            let write: Write = serde_json::from_slice(&bounded_file(&args[5], 16384)?)?;
            let pass = password("Vault password: ")?;
            let key = logos_registry_sdk::publisher::read_signing_key(
                Path::new(&args[4]),
                pass.as_bytes(),
            )?;
            let transaction = node.sign_write(program, &key, &write)?;
            let hash = transaction.hash();
            eprintln!(
                "Transaction hash: {}. If submission times out, check status before retrying.",
                serde_json::to_string(&hash)?
            );
            node.submit(&transaction)?;
            println!(
                "{}",
                serde_json::json!({"transaction":hash,"status":"submitted","confirmed":false})
            );
        }
        Some("status") if args.len() == 4 => {
            let hash: common::HashType = serde_json::from_value(serde_json::json!(args[3]))?;
            let confirmed = HttpNode::new(&args[2])?.confirmed(hash)?;
            println!(
                "{}",
                serde_json::json!({"transaction":hash,"status":if confirmed {"included_by_sequencer"} else {"not_included"}})
            );
        }
        Some("verify-image") if args.len() == 4 => {
            let mut elf = Vec::new();
            std::fs::File::open(&args[2])?
                .take(64 * 1024 * 1024 + 1)
                .read_to_end(&mut elf)?;
            let result = verify_image(&elf, &parse_program(&args[3])?)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            if !result.matches {
                return Err("Image ID does not match".into());
            }
        }
        Some("lookup") if args.len() == 7 => {
            let registry = Registry {
                reader: HttpNode::new(&args[2])?,
                program: parse_program(&args[3])?,
            };
            let entry = registry.lookup(
                &program_bytes(&parse_program(&args[4])?),
                AccountId::from_str(&args[5])?.value(),
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&resolve(entry, &HttpNode::new(&args[6])?))?
            );
        }
        Some("page") if (5..=7).contains(&args.len()) => {
            let registry = Registry {
                reader: HttpNode::new(&args[2])?,
                program: parse_program(&args[3])?,
            };
            let result = registry.search_page(
                args[4].parse()?,
                args.get(5).map_or("", String::as_str),
                args.get(6).map_or("", String::as_str),
            )?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Some("validate-metadata") if args.len() == 3 => {
            let mut bytes = Vec::new();
            std::fs::File::open(&args[2])?
                .take(8193)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 8192 {
                return Err("Metadata exceeds 8192 bytes".into());
            }
            let metadata: logos_prize_registry::Metadata = serde_json::from_slice(&bytes)?;
            metadata.validate()?;
            println!("{}", serde_json::to_string_pretty(&metadata)?);
        }
        Some("help" | "--help") | None => println!(
            "Registry CLI\n\n  registry lookup RPC REGISTRY_HEX TARGET_HEX AUTHOR_BASE58 STORAGE_API\n  registry page RPC REGISTRY_HEX PAGE [NAME] [AUTHOR]\n  registry verify-image PROGRAM_BIN PROGRAM_HEX\n  registry validate-metadata FILE\n\nSTORAGE_API example: http://127.0.0.1:8080/api/storage/v1\nProgram hex is the RISC Zero image ID byte representation.\nregistry key-import VAULT\n  registry write RPC REGISTRY_HEX VAULT WRITE_JSON\n  registry status RPC TRANSACTION_HASH\n\nwrite uses an explicit JSON operation; see docs/registry-writes.md.\nregistry build-recipe RPC REGISTRY_HEX TARGET_HEX AUTHOR_BASE58 STORAGE_API\n  registry verify-source RPC REGISTRY_HEX TARGET_HEX AUTHOR_BASE58 STORAGE_API CHECKOUT RECIPE_JSON RECEIPTS_DIR\n  registry source-status RPC REGISTRY_HEX TARGET_HEX AUTHOR_BASE58 RECEIPTS_DIR\n  registry package-image USER_ELF KERNEL_ELF OUTPUT_BIN\n\nverify-source executes the explicitly reviewed recipe locally; see docs/source-verification.md."
        ),
        _ => return Err("Invalid arguments; use registry --help".into()),
    }
    Ok(())
}
fn main() {
    if let Err(e) = run(std::env::args().collect()) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
