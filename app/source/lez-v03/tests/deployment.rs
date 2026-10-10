// SPDX-License-Identifier: MIT OR Apache-2.0
use lee_core_v03::program::{ProgramHeader, ProgramSegment};
use logos_lez_v03::{
    AccountData, AccountId, AccountView, Error, Result,
    deployment::{self, DeploymentReader, LOADER},
};
use std::{cell::RefCell, collections::BTreeMap};

fn id(n: u8) -> AccountId {
    AccountId::from_bytes([n; 32])
}
fn upstream(id: AccountId) -> lee_core_v03::account::AccountId {
    lee_core_v03::account::AccountId::new(id.bytes())
}
struct Reader {
    shards: BTreeMap<AccountId, Vec<u8>>,
    reads: RefCell<Vec<AccountId>>,
    change_header: bool,
}
impl DeploymentReader for Reader {
    fn loader_view(&self, account: AccountId) -> Result<AccountView> {
        let repeated = self.reads.borrow().contains(&account);
        self.reads.borrow_mut().push(account);
        let data = self
            .shards
            .get(&account)
            .ok_or(Error::Invalid("fixture missing"))?
            .clone();
        Ok(AccountView {
            nonce: u128::from(self.change_header && account == id(1) && repeated),
            data: AccountData {
                shards: BTreeMap::from([(LOADER, data)]),
            },
        })
    }
}
// Minimal ELF32 RISC-V executable. Only image computation is tested; no claim
// that this synthetic instruction sequence implements a useful guest.
fn elf() -> Vec<u8> {
    let mut bytes = vec![0; 88];
    bytes[..7].copy_from_slice(b"\x7fELF\x01\x01\x01");
    for (offset, value) in [(16, 2u16), (18, 243), (40, 52), (42, 32), (44, 1)] {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [
        (20, 1u32),
        (24, 0x00200400),
        (28, 52),
        (52, 1),
        (56, 84),
        (60, 0x00200400),
        (64, 0x00200400),
        (68, 4),
        (72, 4),
        (76, 5),
        (80, 4),
        (84, 0x00000073),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}
fn fixture() -> (Reader, [u32; 8]) {
    let elf = elf();
    let image = risc0_binfmt::ProgramBinary::new(&elf, risc0_zkos_v1compat::V1COMPAT_ELF)
        .compute_image_id()
        .unwrap()
        .into();
    let header = ProgramHeader {
        image_id: image,
        program_first_segment: upstream(id(2)),
        immutable: false,
    };
    let shards = BTreeMap::from([
        (id(1), header.to_bytes()),
        (
            id(2),
            ProgramSegment {
                bytecode: elf[..44].to_vec(),
                next_segment: Some(upstream(id(3))),
            }
            .to_bytes(),
        ),
        (
            id(3),
            ProgramSegment {
                bytecode: elf[44..].to_vec(),
                next_segment: None,
            }
            .to_bytes(),
        ),
    ]);
    (
        Reader {
            shards,
            reads: RefCell::new(Vec::new()),
            change_header: false,
        },
        image,
    )
}
#[test]
fn reconstructs_linked_elf_with_protocol_kernel_and_rereads_header() {
    let (reader, image) = fixture();
    let observed = deployment::inspect(&reader, id(1), image).unwrap();
    assert_eq!(observed.image_id, image);
    assert_eq!(observed.segments, vec![id(2), id(3)]);
    assert_eq!(observed.user_elf_bytes, 88);
    assert!(!observed.immutable);
    assert_eq!(*reader.reads.borrow(), vec![id(1), id(2), id(3), id(1)]);
}
#[test]
fn rejects_changed_review_header_chain_and_bytecode() {
    let (reader, _) = fixture();
    assert!(deployment::inspect(&reader, id(1), [0; 8]).is_err());
    assert_eq!(reader.reads.borrow().len(), 1);
    let (mut reader, image) = fixture();
    reader.change_header = true;
    assert!(
        deployment::inspect(&reader, id(1), image)
            .unwrap_err()
            .to_string()
            .contains("changed")
    );
    let (mut reader, image) = fixture();
    reader.shards.get_mut(&id(3)).unwrap()[44] ^= 1;
    assert!(deployment::inspect(&reader, id(1), image).is_err());
    let (mut reader, image) = fixture();
    reader.shards.insert(
        id(3),
        ProgramSegment {
            bytecode: vec![],
            next_segment: Some(upstream(id(2))),
        }
        .to_bytes(),
    );
    assert!(
        deployment::inspect(&reader, id(1), image)
            .unwrap_err()
            .to_string()
            .contains("cyclic")
    );
}
#[test]
fn rejects_missing_oversized_and_malformed_shards_and_reserved_addresses() {
    for target in [logos_lez_v03::NATIVE_PROGRAM, LOADER] {
        let (reader, image) = fixture();
        assert!(deployment::inspect(&reader, target, image).is_err());
        assert!(reader.reads.borrow().is_empty());
    }
    for data in [
        vec![],
        vec![0xff; 4],
        vec![0; logos_lez_v03::MAX_SHARD_BYTES + 1],
    ] {
        let (mut reader, image) = fixture();
        reader.shards.insert(id(2), data);
        assert!(deployment::inspect(&reader, id(1), image).is_err());
    }
    let (mut reader, image) = fixture();
    reader.shards.remove(&id(3));
    assert!(deployment::inspect(&reader, id(1), image).is_err());
}
#[test]
fn bounds_segment_requests_before_following_excessive_chain() {
    let (mut reader, image) = fixture();
    for n in 2..=22 {
        reader.shards.insert(
            id(n),
            ProgramSegment {
                bytecode: vec![],
                next_segment: Some(upstream(id(n + 1))),
            }
            .to_bytes(),
        );
    }
    assert!(deployment::inspect(&reader, id(1), image).is_err());
    assert_eq!(reader.reads.borrow().len(), 21);
}
