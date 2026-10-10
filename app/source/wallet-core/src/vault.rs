// SPDX-License-Identifier: MIT OR Apache-2.0
//! Versioned encrypted wallet payloads for local storage or opt-in remote backup.
//! Callers own LEZ key serialization. No plaintext persistence is provided.
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use rand_core::{OsRng, RngCore};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;
const MAGIC: &[u8; 8] = b"LGSVLT01";
const HEADER: usize = 8 + 16 + 24;
const MAX: usize = 4 * 1024 * 1024;
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("Invalid vault or unsupported format")]
    Invalid,
    #[error("Incorrect password or damaged vault")]
    Authentication,
    #[error("Random number generator unavailable")]
    Entropy,
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}
pub type Result<T> = std::result::Result<T, VaultError>;
fn key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if password.is_empty() || password.len() > 1024 {
        return Err(VaultError::Invalid);
    }
    let params = Params::new(64 * 1024, 3, 1, Some(32)).map_err(|_| VaultError::Invalid)?;
    let mut key = Zeroizing::new([0; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|_| VaultError::Invalid)?;
    Ok(key)
}
pub fn seal(password: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.len() > MAX {
        return Err(VaultError::Invalid);
    }
    let mut salt = [0; 16];
    let mut nonce = [0; 24];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| VaultError::Entropy)?;
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| VaultError::Entropy)?;
    let k = key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(k.as_ref()).map_err(|_| VaultError::Invalid)?;
    let mut header = Vec::from(MAGIC.as_slice());
    header.extend(salt);
    header.extend(nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| VaultError::Authentication)?;
    header.extend(ciphertext);
    Ok(header)
}
pub fn open(password: &[u8], bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if bytes.len() < HEADER + 16 || bytes.len() > HEADER + MAX + 16 || &bytes[..8] != MAGIC {
        return Err(VaultError::Invalid);
    }
    let k = key(password, &bytes[8..24])?;
    let cipher = XChaCha20Poly1305::new_from_slice(k.as_ref()).map_err(|_| VaultError::Invalid)?;
    cipher
        .decrypt(
            XNonce::from_slice(&bytes[24..HEADER]),
            Payload {
                msg: &bytes[HEADER..],
                aad: &bytes[..HEADER],
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| VaultError::Authentication)
}
/// Creates a NEW encrypted file. Refuses to replace existing files or follow symlinks.
/// Explicit replacement/rotation needs a separate transaction in the wallet store.
pub fn create_file(path: &Path, password: &[u8], plaintext: &[u8]) -> Result<()> {
    let ciphertext = seal(password, plaintext)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&ciphertext)?;
    file.sync_all()?;
    Ok(())
}
pub fn read_file(path: &Path, password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take((HEADER + MAX + 17) as u64)
        .read_to_end(&mut bytes)?;
    open(password, &bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_roundtrip_and_tamper_detection() {
        let blob = seal(b"fixture passphrase", b"fixture private material").unwrap();
        assert!(!blob.windows(7).any(|v| v == b"private"));
        assert_eq!(
            &*open(b"fixture passphrase", &blob).unwrap(),
            b"fixture private material"
        );
        assert!(open(b"wrong password", &blob).is_err());
        let mut changed = blob.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(open(b"fixture passphrase", &changed).is_err());
        assert_ne!(
            blob,
            seal(b"fixture passphrase", b"fixture private material").unwrap()
        );
    }
    #[test]
    fn oversized_and_unsupported_headers_fail_before_kdf() {
        assert!(open(b"x", b"bad header").is_err());
        assert!(seal(b"", b"secret").is_err());
        assert!(seal(b"password", &vec![0; MAX + 1]).is_err());
    }
}
