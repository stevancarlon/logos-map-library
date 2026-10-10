// SPDX-License-Identifier: MIT OR Apache-2.0
use logos_prize_registry::{Entry, Metadata};
use logos_registry_sdk::{StorageReader, verification::*};
use std::{path::Path, process::Command};

struct RecipeStorage(BuildRecipe);
impl StorageReader for RecipeStorage {
    fn read(&self, _: &str, _: usize) -> logos_registry_sdk::Result<Vec<u8>> {
        Ok(serde_json::to_vec(&self.0).unwrap())
    }
}
fn entry() -> Entry {
    Entry {
        schema: 1,
        program_id: [1; 32],
        registrant: [2; 32],
        ordinal: 0,
        revision: 0,
        submitted_at: 1,
        metadata: Metadata {
            name: "Local source fixture".into(),
            version: "1".into(),
            author: "Fixture".into(),
            description: "Not a deployed program or adoption evidence".into(),
            tags: vec![],
            idl_cid: "bafyFixtureIDL".into(),
            source_cid: "bafyFixtureSource".into(),
            source_commit: "a".repeat(40),
            build_config_cid: "bafyFixtureBuild".into(),
        },
    }
}
fn recipe() -> BuildRecipe {
    BuildRecipe {
        schema: 1,
        command: vec!["false".into()],
        artifact: "program.bin".into(),
        toolchain: "test fixture".into(),
    }
}
#[test]
fn receipt_is_local_to_exact_endpoint_author_revision_and_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let entry = entry();
    let registry = "11".repeat(32);
    assert!(
        lookup(dir.path(), "http://127.0.0.1:1", &registry, &entry)
            .unwrap()
            .is_none()
    );
    let invalid_recipe = BuildRecipe {
        artifact: "../escape".into(),
        ..recipe()
    };
    assert!(invalid_recipe.validate().is_err());
    assert!(
        rebuild(
            "http://127.0.0.1:1",
            &registry,
            &entry,
            dir.path(),
            &recipe(),
            &RecipeStorage(recipe())
        )
        .is_err()
    );
    let wrong = BuildRecipe {
        command: vec!["true".into()],
        ..recipe()
    };
    assert!(
        rebuild(
            "http://127.0.0.1:1",
            &registry,
            &entry,
            dir.path(),
            &wrong,
            &RecipeStorage(recipe())
        )
        .unwrap_err()
        .to_string()
        .contains("differs")
    );
}
fn git(dir: &Path, args: &[&str]) -> String {
    let result = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap().trim().to_owned()
}

/// Compiles a tiny RISC-V assembly fixture twice and packages it with the real
/// RISC Zero compatibility kernel. This is rebuild evidence, not LEZ execution.
#[test]
#[ignore = "Requires clang, ld.lld and RISC0_KERNEL_ELF; run explicitly in integration checks"]
fn actual_compiler_rebuild_receipt_and_invalidation() {
    let kernel = std::env::var("RISC0_KERNEL_ELF").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let receipts = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("main.S"),
        ".global _start\n.text\n_start:\n li a0, 0\n ecall\n",
    )
    .unwrap();
    std::fs::write(dir.path().join(".gitignore"), "*.elf\n*.bin\n").unwrap();
    std::fs::write(dir.path().join("build.sh"),"#!/bin/sh\nset -eu\nclang --target=riscv32 -march=rv32im -mabi=ilp32 -nostdlib -fuse-ld=lld -Wl,-Ttext=0x200800 main.S -o program.elf\n\"$1\" package-image program.elf \"$2\" program.bin\n").unwrap();
    git(dir.path(), &["init", "-q"]);
    git(dir.path(), &["add", "."]);
    git(
        dir.path(),
        &[
            "-c",
            "user.name=Local test fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "Compiler fixture, not adoption history",
        ],
    );
    let mut entry = entry();
    entry.metadata.source_commit = git(dir.path(), &["rev-parse", "HEAD"]);
    let recipe = BuildRecipe {schema:1,command:vec!["sh".into(),"build.sh".into(),env!("CARGO_BIN_EXE_registry").into(),kernel],artifact:"program.bin".into(),toolchain:"Installed clang/ld.lld and explicitly supplied compatibility kernel; local fixture only".into()};
    assert!(
        Command::new(&recipe.command[0])
            .args(&recipe.command[1..])
            .current_dir(dir.path())
            .status()
            .unwrap()
            .success()
    );
    let original = std::fs::read(dir.path().join("program.bin")).unwrap();
    let image = risc0_binfmt::compute_image_id(&original).unwrap();
    entry.program_id.copy_from_slice(image.as_bytes());
    std::fs::remove_file(dir.path().join("program.bin")).unwrap();
    std::fs::remove_file(dir.path().join("program.elf")).unwrap();
    let registry = "11".repeat(32);
    let endpoint = "http://127.0.0.1:1";
    let receipt = rebuild(
        endpoint,
        &registry,
        &entry,
        dir.path(),
        &recipe,
        &RecipeStorage(recipe.clone()),
    )
    .unwrap();
    assert_eq!(
        original,
        std::fs::read(dir.path().join("program.bin")).unwrap()
    );
    save(receipts.path(), &receipt).unwrap();
    assert!(save(receipts.path(), &receipt).is_err());
    let program = logos_registry_sdk::parse_program(&registry).unwrap();
    let config = ReviewConfig::new(
        &registry,
        receipts.path().into(),
        std::collections::BTreeMap::from([(entry.program_id, entry.registrant)]),
    )
    .unwrap();
    let mut reader = ReviewReader {
        entry: entry.clone(),
        program,
        owner: program,
    };
    let review = config.inspect(&reader, endpoint, &entry.program_id);
    assert!(
        matches!(&review.state, SourceState::Registered { local_rebuild: Some(found), .. } if found.as_ref() == &receipt)
    );
    reader.entry.revision += 1;
    assert!(matches!(
        config.inspect(&reader, endpoint, &entry.program_id).state,
        SourceState::Registered {
            local_rebuild: None,
            ..
        }
    ));
    reader.entry = entry.clone();
    assert!(matches!(
        config
            .inspect(&reader, "http://other-fixture.invalid", &entry.program_id)
            .state,
        SourceState::Registered {
            local_rebuild: None,
            ..
        }
    ));

    assert!(
        lookup(receipts.path(), endpoint, &registry, &entry)
            .unwrap()
            .is_some()
    );
    assert!(
        lookup(receipts.path(), "http://127.0.0.1:2", &registry, &entry)
            .unwrap()
            .is_none()
    );
    let mut changed = entry.clone();
    changed.revision += 1;
    assert!(
        lookup(receipts.path(), endpoint, &registry, &changed)
            .unwrap()
            .is_none()
    );
    changed = entry.clone();
    changed.registrant = [9; 32];
    assert!(
        lookup(receipts.path(), endpoint, &registry, &changed)
            .unwrap()
            .is_none()
    );
    changed = entry.clone();
    changed.metadata.source_cid.push('x');
    assert!(
        lookup(receipts.path(), endpoint, &registry, &changed)
            .unwrap()
            .is_none()
    );
    std::fs::remove_file(dir.path().join("program.bin")).unwrap();
    std::fs::remove_file(dir.path().join("program.elf")).unwrap();
    changed = entry.clone();
    changed.program_id = [8; 32];
    assert!(
        rebuild(
            endpoint,
            &registry,
            &changed,
            dir.path(),
            &recipe,
            &RecipeStorage(recipe.clone())
        )
        .unwrap_err()
        .to_string()
        .contains("differs")
    );
    std::fs::remove_file(dir.path().join("program.bin")).unwrap();
    std::fs::remove_file(dir.path().join("program.elf")).unwrap();
    std::fs::write(dir.path().join("main.S"), "modified source").unwrap();
    assert!(
        rebuild(
            endpoint,
            &registry,
            &entry,
            dir.path(),
            &recipe,
            &RecipeStorage(recipe.clone())
        )
        .unwrap_err()
        .to_string()
        .contains("modified")
    );
}

struct ReviewReader {
    entry: Entry,
    program: [u32; 8],
    owner: [u32; 8],
}
impl logos_registry_sdk::AccountReader for ReviewReader {
    fn account(&self, id: lee::AccountId) -> logos_registry_sdk::Result<lee::Account> {
        assert_eq!(
            id,
            logos_registry_sdk::entry_address(
                &self.program,
                &self.entry.program_id,
                &self.entry.registrant
            )
        );
        Ok(lee::Account {
            program_owner: self.owner,
            data: borsh::to_vec(&self.entry).unwrap().try_into().unwrap(),
            ..Default::default()
        })
    }
}
#[test]
fn wallet_source_review_checks_registration_and_never_promotes_assertions_to_rebuilds() {
    let receipts = tempfile::tempdir().unwrap();
    let entry = entry();
    let program = [7; 8];
    let registry = hex::encode(logos_registry_sdk::program_bytes(&program));
    assert!(ReviewConfig::new(&registry, "relative-path".into(), Default::default()).is_err());
    assert!(ReviewConfig::new("not-an-image", receipts.path().into(), Default::default()).is_err());
    let config = ReviewConfig::new(
        &registry,
        receipts.path().into(),
        std::collections::BTreeMap::from([(entry.program_id, entry.registrant)]),
    )
    .unwrap();
    let mut reader = ReviewReader {
        entry: entry.clone(),
        program,
        owner: program,
    };
    let endpoint = "http://fixture.invalid";
    let first = config.inspect(&reader, endpoint, &entry.program_id);
    let SourceState::Registered {
        local_rebuild,
        context_sha256,
        ..
    } = &first.state
    else {
        panic!("{first:?}")
    };
    assert!(local_rebuild.is_none());
    assert_eq!(first.program, hex::encode(entry.program_id));
    assert_ne!(
        first,
        config.inspect(&reader, "http://other-fixture.invalid", &entry.program_id)
    );
    reader.entry.revision += 1;
    assert_ne!(first, config.inspect(&reader, endpoint, &entry.program_id));
    reader.entry = entry.clone();
    reader.entry.metadata.source_cid.push('X');
    assert_ne!(first, config.inspect(&reader, endpoint, &entry.program_id));
    reader.entry = entry.clone();
    reader.owner = [9; 8];
    assert_eq!(
        config.inspect(&reader, endpoint, &entry.program_id).state,
        SourceState::Unavailable
    );
    reader.owner = program;
    std::fs::write(
        receipts.path().join(format!("{context_sha256}.json")),
        b"invalid local receipt",
    )
    .unwrap();
    assert_eq!(
        config.inspect(&reader, endpoint, &entry.program_id).state,
        SourceState::Unavailable
    );
    // No selected registration means no RPC, even when that reader would fail.
    assert_eq!(
        config.inspect(&reader, endpoint, &[99; 32]).state,
        SourceState::NoSelectedRegistration
    );
}
