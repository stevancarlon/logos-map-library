// SPDX-License-Identifier: MIT OR Apache-2.0
use logos_map_distribution::*;
use std::{
    error::Error,
    io::{BufRead, Read, Write},
};
fn run(args: Vec<String>) -> std::result::Result<(), Box<dyn Error>> {
    match args.get(1).map(String::as_str) {
        Some(operation @ ("host" | "host-local")) if args.len() == 11 => {
            let registry = logos_map_sdk::MapRegistry {
                reader: logos_map_sdk::HttpNode::new(&args[2])?,
                program: logos_registry_sdk::parse_program(&args[3])?,
            };
            // Fail before downloading/uploading if deployment setup is absent.
            registry.catalog()?;
            let storage = transport::StorageNode::new(&args[4])?;
            let region = importer::supported_region(&args[6])?;
            let version = args[7].parse()?;
            let path = std::path::Path::new(&args[8]);
            let limit = args[9].parse()?;
            if operation == "host" {
                eprintln!(
                    "Fetching the selected dated Geofabrik extract, then uploading it to public Storage."
                );
                importer::fetch_dated(&region, version, path, limit)?;
            }
            let snapshot = hosting::store_local(
                &storage,
                &region,
                version,
                path,
                limit,
                std::path::Path::new(&args[10]),
            )?;
            eprintln!(
                "Stored and checksum verified; not yet registered:\n{}",
                serde_json::to_string_pretty(&snapshot)?
            );
            eprintln!(
                "Registry: {} at {}. Registration may create a page and then announce this snapshot. This is a hosting assertion, not proof of continued availability.",
                args[3], args[2]
            );
            let password = zeroize::Zeroizing::new(logos_registry_sdk::terminal::prompt_secret(
                "Vault password: ",
            )?);
            let key = logos_registry_sdk::publisher::read_signing_key(
                std::path::Path::new(&args[5]),
                password.as_bytes(),
            )?;
            drop(password);
            if !approve_host()? {
                return Err("Canceled registration. The uploaded CID above remains stored; no registry transaction was submitted.".into());
            }
            let timestamp = u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_millis(),
            )?;
            let transactions = registry.register_hosted(&key, vec![snapshot.clone()], timestamp)?;
            println!(
                "{}",
                serde_json::json!({"snapshot":snapshot,"transactions":transactions,"status":"included","scope":"configured sequencer inclusion; not consensus finality or continued hosting"})
            );
        }
        Some("fetch-region") if args.len() == 5 => {
            let region = importer::supported_region(&args[2])?;
            let result =
                importer::fetch(&region, std::path::Path::new(&args[3]), args[4].parse()?)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Some("fetch") if args.len() == 6 => {
            let mut bytes = Vec::new();
            std::fs::File::open(&args[2])?
                .take(16 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            let catalog = parse_index(&bytes)?;
            let region = catalog
                .regions
                .iter()
                .find(|r| r.path == args[3])
                .ok_or("Region not present in the supported catalog")?;
            eprintln!("Fetching explicitly from Geofabrik; no upload or registration will occur.");
            let imported =
                importer::fetch(region, std::path::Path::new(&args[4]), args[5].parse()?)?;
            println!("{}", serde_json::to_string_pretty(&imported)?);
        }
        Some("write") if args.len() == 6 => {
            let registry = logos_map_sdk::MapRegistry {
                reader: logos_map_sdk::HttpNode::new(&args[2])?,
                program: logos_registry_sdk::parse_program(&args[3])?,
            };
            let mut bytes = Vec::new();
            std::fs::File::open(&args[5])?
                .take(32769)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 32768 {
                return Err("Write input exceeds limit".into());
            }
            let operation: logos_map_sdk::MapWrite = serde_json::from_slice(&bytes)?;
            let password = zeroize::Zeroizing::new(logos_registry_sdk::terminal::prompt_secret(
                "Vault password: ",
            )?);
            let key = logos_registry_sdk::publisher::read_signing_key(
                std::path::Path::new(&args[4]),
                password.as_bytes(),
            )?;
            let transaction = registry.sign(&key, &operation)?;
            let hash = transaction.hash();
            eprintln!(
                "Transaction hash: {}. Check status before retrying if submission times out.",
                serde_json::to_string(&hash)?
            );
            registry.reader.submit(&transaction)?;
            println!(
                "{}",
                serde_json::json!({"transaction":hash,"status":"submitted","confirmed":false})
            );
        }
        Some("upload") if args.len() == 7 => {
            let result = transport::StorageNode::new(&args[2])?.upload_verified(
                std::path::Path::new(&args[3]),
                parse_md5_sidecar(&args[4])?,
                args[5].parse()?,
                std::path::Path::new(&args[6]),
            )?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Some("download-snapshot") if args.len() == 6 => {
            if args[3].len() > 32768 {
                return Err("Snapshot JSON exceeds limit".into());
            }
            let snapshot: logos_map_sdk::Snapshot = serde_json::from_str(&args[3])?;
            let result = transport::StorageNode::new(&args[2])?.download_snapshot(
                &snapshot,
                args[4].parse()?,
                std::path::Path::new(&args[5]),
            )?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Some("download") if args.len() == 7 => {
            let result = transport::StorageNode::new(&args[2])?.download_verified(
                &args[3],
                parse_md5_sidecar(&args[4])?,
                args[5].parse()?,
                std::path::Path::new(&args[6]),
            )?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Some("registry-page") if args.len() == 7 => {
            let registry = logos_map_sdk::MapRegistry {
                reader: logos_map_sdk::HttpNode::new(&args[2])?,
                program: logos_registry_sdk::parse_program(&args[3])?,
            };
            let filter = match args[5].as_str() {
                "region" => logos_map_sdk::Filter {
                    region: Some(&args[6]),
                    ..Default::default()
                },
                "parent" => logos_map_sdk::Filter {
                    parent: Some(&args[6]),
                    ..Default::default()
                },
                "cid" => logos_map_sdk::Filter {
                    cid: Some(&args[6]),
                    ..Default::default()
                },
                "all" => logos_map_sdk::Filter::default(),
                _ => return Err("Expected region, parent, cid or all".into()),
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&registry.query(args[4].parse()?, &filter)?)?
            );
        }
        Some("regions") if args.len() == 3 => {
            let mut bytes = Vec::new();
            std::fs::File::open(&args[2])?
                .take(16 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            println!("{}", serde_json::to_string_pretty(&parse_index(&bytes)?)?);
        }
        Some("verify") if args.len() == 5 => {
            let checksum = parse_md5_sidecar(&args[3])?;
            let limit = args[4].parse()?;
            let verified = verify_copy(
                std::fs::File::open(&args[2])?,
                std::io::sink(),
                checksum,
                limit,
            )?;
            println!("{}", serde_json::to_string_pretty(&verified)?);
        }
        None | Some("help" | "--help") => println!(
            "Maps CLI\n  maps host RPC REGISTRY_HEX STORAGE_API KEY_VAULT REGION_PATH YYYYMMDD DESTINATION MAX_BYTES SCRATCH_DIR\n  maps host-local RPC REGISTRY_HEX STORAGE_API KEY_VAULT REGION_PATH YYYYMMDD LOCAL_PBF MAX_BYTES SCRATCH_DIR\n  maps regions INDEX_JSON\n  maps fetch INDEX_JSON REGION_PATH DESTINATION MAX_BYTES\n  maps verify PBF EXPECTED_MD5 MAX_BYTES\n  maps registry-page RPC REGISTRY_HEX PAGE region|parent|cid|all VALUE\n\nmaps upload STORAGE_API PBF EXPECTED_MD5 MAX_BYTES SCRATCH_DIR\n  maps download STORAGE_API CID EXPECTED_MD5 MAX_BYTES DESTINATION\n  maps download-snapshot STORAGE_API SNAPSHOT_JSON MAX_BYTES DESTINATION\n\nmaps write RPC REGISTRY_HEX KEY_VAULT WRITE_JSON\n\nUpload alone does not register content. Use registry status RPC HASH to check write inclusion."
        ),
        _ => return Err("Invalid arguments".into()),
    }
    Ok(())
}
fn main() {
    if let Err(e) = run(std::env::args().collect()) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn approve_host() -> std::result::Result<bool, Box<dyn Error>> {
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")?;
    tty.write_all(b"Type APPROVE to register this stored snapshot, or anything else to cancel: ")?;
    tty.flush()?;
    let mut answer = String::new();
    std::io::BufReader::new(tty)
        .take(128)
        .read_line(&mut answer)?;
    Ok(answer.trim() == "APPROVE")
}
