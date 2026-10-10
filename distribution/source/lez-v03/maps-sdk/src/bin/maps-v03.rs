// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared SDK command adapter for the distribution CLI and asynchronous native bridge.
use logos_map_distribution::{parse_md5_sidecar, verify_copy};
use logos_maps_v03_sdk::{
    Filter, Registry, Snapshot,
    distribution::{self, Distribution, StorageNode},
    rpc::Node,
};
use serde_json::{Value, json};
use std::{
    error::Error,
    fs::File,
    io::{Read, Write},
    path::Path,
};
fn registry(rpc: &str, program: &str) -> Result<Registry<Node>, Box<dyn Error>> {
    Ok(Registry {
        reader: Node::new(rpc)?,
        program: program.parse()?,
    })
}
fn run(a: &[String]) -> Result<Value, Box<dyn Error>> {
    match a.get(1).map(String::as_str) {
        Some("catalog") if a.len()==2=>Ok(logos_maps_v03_sdk::native::request(r#"{"method":"catalog"}"#)?),
        Some("discover-versions") if a.len()==2=>Ok(serde_json::to_value(distribution::discover_versions()?)?),
        Some("discover") if a.len()==2=>Ok(serde_json::to_value(distribution::fetch_catalog()?)?),
        Some("latest-version") if a.len()==3=>Ok(serde_json::to_value(distribution::latest_version(&distribution::importer::supported_region(&a[2])?)?)?),
        Some("registry-page") if a.len()==7=>{
            let filter=match a[5].as_str() {
                "region"=>Filter {region:Some(&a[6]),..Default::default()},
                "parent"=>Filter {parent:Some(&a[6]),..Default::default()},
                "cid"=>Filter {cid:Some(&a[6]),..Default::default()},
                "all"=>Filter::default(),_=>return Err("Expected region, parent, cid or all".into())};
            Ok(serde_json::to_value(registry(&a[2],&a[3])?.query(a[4].parse()?,&filter)?)?)
        }
        Some("verify") if a.len()==5=>Ok(serde_json::to_value(verify_copy(File::open(&a[2])?,std::io::sink(),parse_md5_sidecar(&a[3])?,a[4].parse()?)?)?),
        Some("fetch-region") if a.len()==5=>Ok(serde_json::to_value(distribution::importer::fetch(&distribution::importer::supported_region(&a[2])?,Path::new(&a[3]),a[4].parse()?)?)?),
        Some("upload") if a.len()==7=>Ok(serde_json::to_value(StorageNode::new(&a[2])?.upload_verified(Path::new(&a[3]),parse_md5_sidecar(&a[4])?,a[5].parse()?,Path::new(&a[6]))?)?),
        Some("download") if a.len()==7=>Ok(serde_json::to_value(StorageNode::new(&a[2])?.download_verified(&a[3],parse_md5_sidecar(&a[4])?,a[5].parse()?,Path::new(&a[6]))?)?),
        Some("download-snapshot") if a.len()==6=>{
            if a[3].len()>32768 {return Err("Snapshot exceeds limit".into())}
            let snapshot:Snapshot=serde_json::from_str(&a[3])?;
            Ok(serde_json::to_value(StorageNode::new(&a[2])?.download_snapshot(&snapshot,a[4].parse()?,Path::new(&a[5]))?)?)
        }
        Some("host-local"|"host-fetch") if a.len()==9 || a.len()==10=>{
            let service=Distribution {registry:registry(&a[2],&a[3])?,storage:StorageNode::new(&a[4])?};
            let region=distribution::importer::supported_region(&a[5])?;
            let version=match a.get(9).filter(|s|!s.is_empty()) {Some(value)=>value.parse()?,None=>distribution::latest_version(&region)?.version};
            let snapshot=if a[1]=="host-local" {
                service.import_and_store(&a[5],version,Path::new(&a[6]),a[7].parse()?,Path::new(&a[8]))?
            } else {
                service.fetch_and_store(&a[5],version,Path::new(&a[6]),a[7].parse()?,Path::new(&a[8]))?
            };
            Ok(json!({"snapshot":snapshot,"registry_status":"not_registered"}))
        }
        Some("updates") if a.len()==6=>{
            if a[4].len()>16384 {return Err("Selection exceeds limit".into())}
            let paths:Vec<String>=serde_json::from_str(&a[4])?;
            Ok(json!({"updates":registry(&a[2],&a[3])?.check_updates(&paths,a[5].parse()?)?}))
        }
        Some("bulk-plan") if a.len()==5=>{
            let catalog=registry(&a[2],&a[3])?.catalog()?;
            Ok(json!({"batches":distribution::batches(catalog.count,a[4].parse()?)?,"catalog_count":catalog.count}))
        }
        Some("store-bulk") if a.len()==8=>{
            let mut bytes=vec![];File::open(&a[5])?.take(65537).read_to_end(&mut bytes)?;
            if bytes.len()>65536 {return Err("Host selection file exceeds limit".into())}
            let items:Vec<distribution::HostItem>=serde_json::from_slice(&bytes)?;
            let distribution=Distribution {registry:registry(&a[2],&a[3])?,storage:StorageNode::new(&a[4])?};
            let outcomes=distribution.store_bulk(&items,a[6].parse()?,Path::new(&a[7]),|outcome| {
                // Report each public CID immediately even if a later item fails or the CLI is canceled.
                eprintln!("{}",json!({"progress":outcome}));true
            })?;
            Ok(json!({"outcomes":outcomes,"registry_status":"not_registered"}))
        }
        _=>Err("Usage: maps-v03 catalog | discover | discover-versions | latest-version REGION | registry-page RPC ACCOUNT PAGE region|parent|cid|all VALUE | verify PBF MD5 MAX_BYTES | fetch-region REGION DESTINATION MAX_BYTES | upload STORAGE_API PBF MD5 MAX_BYTES SCRATCH | download STORAGE_API CID MD5 MAX_BYTES DESTINATION | download-snapshot STORAGE_API SNAPSHOT_JSON MAX_BYTES DESTINATION | host-local|host-fetch RPC ACCOUNT STORAGE_API REGION FILE MAX_BYTES SCRATCH [YYYYMMDD] | updates RPC ACCOUNT PATHS_JSON MAX_PAGES | bulk-plan RPC ACCOUNT SELECTED_COUNT | store-bulk RPC ACCOUNT STORAGE_API ITEMS_JSON_FILE MAX_BYTES SCRATCH".into())
    }
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    match run(&args) {
        Ok(value) => {
            println!("{value}");
            let _ = std::io::stdout().flush();
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1)
        }
    }
}
