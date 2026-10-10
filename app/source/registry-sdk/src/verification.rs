// SPDX-License-Identifier: MIT OR Apache-2.0
//! Explicit local source rebuilds and revision-bound, local-only verification receipts.
//! A build command runs with the user's privileges; it is never fetched or run implicitly.
use crate::{Error, Result, StorageReader, parse_program, verify_image};
use logos_prize_registry::Entry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildRecipe {
    pub schema: u16,
    /// Executable and arguments. No implicit shell expansion.
    pub command: Vec<String>,
    /// Relative output path inside the checkout; must not exist before building.
    pub artifact: String,
    /// Human-readable toolchain/container pin reviewed by the user.
    pub toolchain: String,
}
impl BuildRecipe {
    pub fn validate(&self) -> Result<()> {
        if self.schema != 1
            || self.command.is_empty()
            || self.command.len() > 64
            || self
                .command
                .iter()
                .any(|v| v.is_empty() || v.len() > 4096 || v.contains('\0'))
            || self.toolchain.is_empty()
            || self.toolchain.len() > 2048
            || self.artifact.is_empty()
            || self.artifact.len() > 1024
            || !Path::new(&self.artifact)
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
        {
            return Err(invalid("Invalid build recipe"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema: u16,
    pub context_sha256: String,
    pub program: String,
    pub source_commit: String,
    pub artifact_sha256: String,
    pub recipe_sha256: String,
    pub verified_at: u64,
    pub status: String,
}
fn invalid(message: impl ToString) -> Error {
    Error::Invalid(message.to_string())
}
fn fingerprint(endpoint: &str, registry: &str, entry: &Entry) -> Result<String> {
    let context = serde_json::to_vec(&(
        "logos.registry.local-source.v1",
        endpoint.trim_end_matches('/'),
        registry,
        entry,
    ))
    .map_err(invalid)?;
    Ok(hex::encode(Sha256::digest(context)))
}
fn git(checkout: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-C")
        .arg(checkout)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(invalid)?;
    if !output.status.success() {
        return Err(invalid("Cannot inspect the local Git checkout"));
    }
    String::from_utf8(output.stdout).map_err(invalid)
}
fn check_source(checkout: &Path, expected: &str) -> Result<()> {
    let top = git(checkout, &["rev-parse", "--show-toplevel"])?;
    if Path::new(top.trim()).canonicalize().map_err(invalid)? != checkout {
        return Err(invalid("Select the Git checkout root, not a subdirectory"));
    }
    if git(checkout, &["rev-parse", "HEAD"])?.trim() != expected.to_ascii_lowercase() {
        return Err(invalid(
            "Checkout commit does not match the registered source commit",
        ));
    }
    if !git(
        checkout,
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?
    .is_empty()
    {
        return Err(invalid("Source checkout has modified or untracked files"));
    }
    // Submodules need explicit materialization and independent commit checking.
    if checkout.join(".gitmodules").exists() {
        return Err(invalid("Submodule verification is not implemented"));
    }
    Ok(())
}

/// Caller must explicitly choose this operation after reviewing the local recipe.
/// This is not a sandbox and does not attest compiler honesty or hermetic builds.
pub fn rebuild(
    endpoint: &str,
    registry: &str,
    entry: &Entry,
    checkout: &Path,
    recipe: &BuildRecipe,
    storage: &impl StorageReader,
) -> Result<Receipt> {
    entry.metadata.validate().map_err(invalid)?;
    parse_program(registry)?;
    recipe.validate()?;
    let recorded: BuildRecipe =
        serde_json::from_slice(&storage.read(&entry.metadata.build_config_cid, 16384)?)
            .map_err(invalid)?;
    if &recorded != recipe {
        return Err(invalid(
            "Reviewed recipe differs from the registered build configuration",
        ));
    }
    let checkout = checkout.canonicalize().map_err(invalid)?;
    check_source(&checkout, &entry.metadata.source_commit)?;
    let artifact = checkout.join(&recipe.artifact);
    if artifact.try_exists().map_err(invalid)? {
        return Err(invalid(
            "Build output already exists; use a fresh checkout/output",
        ));
    }
    if !git(
        &checkout,
        &["ls-files", "--others", "--ignored", "--exclude-standard"],
    )?
    .is_empty()
    {
        return Err(invalid(
            "Use a fresh checkout without pre-existing ignored build inputs or outputs",
        ));
    }
    let status = Command::new(&recipe.command[0])
        .args(&recipe.command[1..])
        .current_dir(&checkout)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(invalid)?;
    if !status.success() {
        return Err(invalid(
            "Source build failed; no verification receipt created",
        ));
    }
    check_source(&checkout, &entry.metadata.source_commit)?;
    let resolved = artifact.canonicalize().map_err(invalid)?;
    if !resolved.starts_with(&checkout) {
        return Err(invalid("Build artifact resolves outside the checkout"));
    }
    let mut bytes = Vec::new();
    File::open(resolved)
        .map_err(invalid)?
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(invalid)?;
    let program = hex::encode(entry.program_id);
    if !verify_image(&bytes, &parse_program(&program)?)?.matches {
        return Err(invalid("Rebuilt image differs from the registered program"));
    }
    Ok(Receipt {
        schema: 1,
        context_sha256: fingerprint(endpoint, registry, entry)?,
        program,
        source_commit: entry.metadata.source_commit.clone(),
        artifact_sha256: hex::encode(Sha256::digest(&bytes)),
        recipe_sha256: hex::encode(Sha256::digest(serde_json::to_vec(recipe).map_err(invalid)?)),
        verified_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(invalid)?
            .as_secs(),
        status: "locally_rebuilt_image_matches".into(),
    })
}
/// Local trusted-user annotations, not portable attestations. Never import receipts
/// from a registry entry or Storage as though the current user rebuilt that source.
pub fn save(directory: &Path, receipt: &Receipt) -> Result<()> {
    if receipt.context_sha256.len() != 64
        || !receipt
            .context_sha256
            .bytes()
            .all(|v| v.is_ascii_hexdigit())
    {
        return Err(invalid("Invalid receipt identifier"));
    }
    std::fs::create_dir_all(directory).map_err(invalid)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(directory.join(format!("{}.json", receipt.context_sha256)))
        .map_err(invalid)?;
    file.write_all(&serde_json::to_vec_pretty(receipt).map_err(invalid)?)
        .map_err(invalid)?;
    file.sync_all().map_err(invalid)?;
    Ok(())
}
pub fn lookup(
    directory: &Path,
    endpoint: &str,
    registry: &str,
    entry: &Entry,
) -> Result<Option<Receipt>> {
    let context = fingerprint(endpoint, registry, entry)?;
    let path = directory.join(format!("{context}.json"));
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(invalid(e)),
    };
    let mut bytes = Vec::new();
    file.take(16385).read_to_end(&mut bytes).map_err(invalid)?;
    if bytes.len() > 16384 {
        return Err(invalid("Verification receipt exceeds limit"));
    }
    let receipt: Receipt = serde_json::from_slice(&bytes).map_err(invalid)?;
    if receipt.schema != 1
        || receipt.context_sha256 != context
        || receipt.program != hex::encode(entry.program_id)
        || receipt.source_commit != entry.metadata.source_commit
        || receipt.status != "locally_rebuilt_image_matches"
    {
        return Err(invalid("Invalid or stale verification receipt"));
    }
    Ok(Some(receipt))
}

/// Wallet-controlled registry selection. Never construct this from a dApp's
/// proposal or import its receipt directory from remote metadata.
#[derive(Clone)]
pub struct ReviewConfig {
    registry: String,
    program: spel_framework::prelude::ProgramId,
    receipts: std::path::PathBuf,
    authors: std::collections::BTreeMap<[u8; 32], [u8; 32]>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SourceState {
    NotChecked,
    NoSelectedRegistration,
    Unavailable,
    Registered {
        registry: String,
        registrant: String,
        revision: u64,
        source_commit: String,
        context_sha256: String,
        /// Some means the local rebuild matched the image. It is not an audit,
        /// deployer attestation, or a receipt supplied by this registry author.
        local_rebuild: Option<Box<Receipt>>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SourceReview {
    pub program: String,
    pub state: SourceState,
}
impl SourceReview {
    pub fn unchecked(program: &[u8; 32]) -> Self {
        Self {
            program: hex::encode(program),
            state: SourceState::NotChecked,
        }
    }
}
impl ReviewConfig {
    pub fn new(
        registry: &str,
        receipts: std::path::PathBuf,
        authors: std::collections::BTreeMap<[u8; 32], [u8; 32]>,
    ) -> Result<Self> {
        if !receipts.is_absolute() || authors.len() > 256 {
            return Err(invalid(
                "Select an absolute local receipt directory and at most 256 registrations",
            ));
        }
        let program = parse_program(registry)?;
        Ok(Self {
            registry: hex::encode(crate::program_bytes(&program)),
            program,
            receipts,
            authors,
        })
    }
    /// Read the exact selected author's registration at the transaction's node.
    /// Reads do not download source, run recipes, or contact a metadata host.
    /// Failure is visibly unverified; a prior verified result is never reused.
    pub fn inspect<R: crate::AccountReader>(
        &self,
        reader: &R,
        endpoint: &str,
        target: &[u8; 32],
    ) -> SourceReview {
        struct Borrowed<'a, R>(&'a R);
        impl<R: crate::AccountReader> crate::AccountReader for Borrowed<'_, R> {
            fn account(
                &self,
                id: spel_framework::prelude::AccountId,
            ) -> Result<spel_framework::prelude::Account> {
                self.0.account(id)
            }
        }
        let Some(author) = self.authors.get(target) else {
            return SourceReview {
                program: hex::encode(target),
                state: SourceState::NoSelectedRegistration,
            };
        };
        let lookup = || -> Result<SourceState> {
            let registry = crate::Registry {
                reader: Borrowed(reader),
                program: self.program,
            };
            let entry = registry.lookup(target, author)?;
            let local_rebuild =
                lookup(&self.receipts, endpoint, &self.registry, &entry)?.map(Box::new);
            Ok(SourceState::Registered {
                registry: self.registry.clone(),
                registrant: spel_framework::prelude::AccountId::new(*author).to_string(),
                revision: entry.revision,
                source_commit: entry.metadata.source_commit.clone(),
                context_sha256: fingerprint(endpoint, &self.registry, &entry)?,
                local_rebuild,
            })
        };
        SourceReview {
            program: hex::encode(target),
            state: lookup().unwrap_or(SourceState::Unavailable),
        }
    }
}
