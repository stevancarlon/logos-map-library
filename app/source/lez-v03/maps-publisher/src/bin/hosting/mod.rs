// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use logos_maps_v03_sdk::distribution::{Distribution, HostItem, HostOutcome, StorageNode};
use std::fs::OpenOptions;

fn save(path: &Path, snapshots: &[Snapshot]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer(file.as_file_mut(), snapshots)?;
    file.as_file_mut().write_all(
        b"
",
    )?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}
pub(super) fn run(a: &[String]) -> Result<serde_json::Value> {
    terminal()?;
    let bulk = a[1] == "host-bulk";
    if a.len() != if bulk { 13 } else { 15 } {
        return Err(HELP.into());
    }
    let (receipt_index, key_index, limit_index) = if bulk { (7, 8, 6) } else { (9, 10, 8) };
    let limit: u64 = a[limit_index].parse()?;
    let _: u64 = a[key_index + 2].parse()?;
    let _: u128 = a[key_index + 3].parse()?;
    let _: u64 = a[key_index + 4].parse()?;
    if limit == 0 || limit > 100_000_000_000 {
        return Err("Per-region limit must be 1–100000000000 bytes".into());
    }
    let service = Distribution {
        registry: Registry {
            reader: Node::new(&a[2])?,
            program: a[3].parse()?,
        },
        storage: StorageNode::new(&a[4])?,
    };
    let mut session = unlock(&a[key_index], &a[key_index + 1])?;
    // Refuse an existing receipt rather than overwriting recovery information.
    let receipt = Path::new(&a[receipt_index]);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut placeholder = options.open(receipt)?;
    placeholder.write_all(
        b"[]
",
    )?;
    placeholder.sync_all()?;
    drop(placeholder);
    let scratch = tempfile::tempdir()?;
    let mut snapshots = vec![];
    let mut outcomes = serde_json::Value::Null;
    if bulk {
        let items: Vec<HostItem> = serde_json::from_slice(&bounded(&a[5])?)?;
        let mut checkpoint_error = None;
        let results = service.store_bulk(&items, limit, scratch.path(), |outcome| {
            eprintln!("HOST OUTCOME {}", serde_json::to_string(outcome).unwrap());
            if let HostOutcome::Stored { snapshot } = outcome {
                snapshots.push(snapshot.clone());
                if let Err(error) = save(receipt, &snapshots) {
                    checkpoint_error = Some(error.to_string());
                    return false;
                }
            }
            true
        })?;
        if let Some(error) = checkpoint_error {
            return Err(format!(
                "Stored CID printed above, but receipt checkpoint failed: {error}"
            )
            .into());
        }
        outcomes = serde_json::to_value(results)?;
    } else {
        let version = a[6].parse()?;
        let snapshot = if a[1] == "host-local" {
            service.import_and_store(&a[5], version, Path::new(&a[7]), limit, scratch.path())?
        } else {
            service.fetch_and_store(&a[5], version, Path::new(&a[7]), limit, scratch.path())?
        };
        eprintln!("HOST STORED {}", serde_json::to_string(&snapshot)?);
        snapshots.push(snapshot);
        save(receipt, &snapshots)?;
    }
    eprintln!(
        "Saved {} stored snapshots to {}. Only these successes will be reviewed; storage alone is not registration.",
        snapshots.len(),
        receipt.display()
    );
    let mut result = if snapshots.is_empty() {
        serde_json::json!({"status":"no_snapshots_stored","complete":false})
    } else {
        publish_all(
            &service.registry,
            &mut session,
            &snapshots,
            &a[key_index + 2],
            &a[key_index + 3],
            &a[key_index + 4],
        )?
    };
    let failures = outcomes.as_array().map_or(0, |rows| {
        rows.iter().filter(|r| r["state"] == "failed").count()
    });
    result["registration_complete"] = result.get("complete").cloned().unwrap_or(false.into());
    if failures > 0 {
        result["complete"] = false.into();
        if result["status"] == "registered" {
            result["status"] = "partially_registered".into();
        }
    }
    result["failed_regions"] = failures.into();
    result["receipt"] = a[receipt_index].clone().into();
    result["hosting_outcomes"] = outcomes;
    result["stored_snapshots"] = serde_json::to_value(snapshots)?;
    Ok(result)
}
