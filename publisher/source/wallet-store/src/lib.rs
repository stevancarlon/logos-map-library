// SPDX-License-Identifier: MIT OR Apache-2.0
//! Atomic encrypted wallet snapshots in SQLite. Keys, labels and grants belong
//! inside the encrypted payload; only format, random store ID and revision are public.
use logos_wallet_policy::vault;
use rand_core::{OsRng, RngCore};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use std::{fs::OpenOptions, path::Path, time::Duration};
use zeroize::Zeroizing;

const APPLICATION_ID: i64 = 0x4c505731;
const PREFIX: &[u8; 8] = b"LPWSQL01";
const MAX_PAYLOAD: usize = 4 * 1024 * 1024 - 32;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("SQLite wallet storage: {0}")]
    Database(#[from] rusqlite::Error),
    #[error(transparent)]
    Vault(#[from] vault::VaultError),
    #[error("Wallet file: {0}")]
    Io(#[from] std::io::Error),
    #[error("Wallet changed in another session; reload before saving")]
    Conflict,
    #[error("Unsupported or invalid wallet store")]
    Invalid,
}
pub type Result<T> = std::result::Result<T, Error>;
pub struct Snapshot {
    pub revision: u64,
    pub payload: Zeroizing<Vec<u8>>,
}
pub struct Store {
    connection: Connection,
}
fn encrypt(password: &[u8], id: &[u8], revision: i64, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD || id.len() != 16 || revision < 0 {
        return Err(Error::Invalid);
    }
    let mut plain = Zeroizing::new(Vec::with_capacity(payload.len() + 32));
    plain.extend_from_slice(PREFIX);
    plain.extend_from_slice(id);
    plain.extend_from_slice(&revision.to_le_bytes());
    plain.extend_from_slice(payload);
    Ok(vault::seal(password, &plain)?)
}
fn decrypt(password: &[u8], id: &[u8], revision: i64, cipher: &[u8]) -> Result<Snapshot> {
    let mut plain = vault::open(password, cipher)?;
    if plain.len() < 32
        || &plain[..8] != PREFIX
        || plain[8..24] != *id
        || plain[24..32] != revision.to_le_bytes()
        || revision < 0
    {
        return Err(Error::Invalid);
    }
    plain.drain(..32);
    Ok(Snapshot {
        revision: revision as u64,
        payload: plain,
    })
}
fn row(connection: &Connection) -> Result<(Vec<u8>, i64, Vec<u8>)> {
    Ok(connection.query_row(
        "SELECT store_id,revision,CASE WHEN length(ciphertext)<=4194384 THEN ciphertext ELSE NULL END FROM wallet_state WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?)
}
impl Store {
    fn connect(path: &Path) -> Result<Connection> {
        if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(Error::Invalid);
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA synchronous=FULL;")?;
        Ok(connection)
    }
    /// Creates a new wallet only. Existing files, including symlinks, are never replaced.
    pub fn create(path: &Path, password: &[u8], payload: &[u8]) -> Result<Self> {
        let mut id = [0u8; 16];
        OsRng.try_fill_bytes(&mut id).map_err(|_| Error::Invalid)?;
        let cipher = encrypt(password, &id, 0, payload)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        file.sync_all()?;
        drop(file);
        let mut connection = Self::connect(path)?;
        connection.execute_batch("PRAGMA journal_mode=DELETE;")?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch("PRAGMA application_id=1280333617; PRAGMA user_version=1; CREATE TABLE wallet_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1),store_id BLOB NOT NULL CHECK(length(store_id)=16),revision INTEGER NOT NULL CHECK(revision>=0),ciphertext BLOB NOT NULL CHECK(length(ciphertext)<=4194384)) STRICT;")?;
        transaction.execute(
            "INSERT INTO wallet_state VALUES (1,?1,0,?2)",
            params![&id[..], cipher],
        )?;
        transaction.commit()?;
        #[cfg(unix)]
        std::fs::File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()?;
        Ok(Self { connection })
    }
    pub fn open(path: &Path) -> Result<Self> {
        let connection = Self::connect(path)?;
        let application: i64 =
            connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if application != APPLICATION_ID || version != 1 {
            return Err(Error::Invalid);
        }
        connection.execute_batch("PRAGMA journal_mode=DELETE;")?;
        Ok(Self { connection })
    }
    pub fn load(&self, password: &[u8]) -> Result<Snapshot> {
        let (id, revision, cipher) = row(&self.connection)?;
        decrypt(password, &id, revision, &cipher)
    }
    /// Password is authenticated before replacing a snapshot. Revision comparison
    /// occurs under an immediate transaction; stale writers never overwrite newer keys.
    pub fn save(&mut self, password: &[u8], expected_revision: u64, payload: &[u8]) -> Result<u64> {
        self.replace(password, password, expected_revision, payload)
    }
    pub fn rotate_password(
        &mut self,
        old: &[u8],
        new: &[u8],
        expected_revision: u64,
    ) -> Result<u64> {
        let snapshot = self.load(old)?;
        if snapshot.revision != expected_revision {
            return Err(Error::Conflict);
        }
        self.replace(old, new, expected_revision, &snapshot.payload)
    }
    fn replace(
        &mut self,
        old: &[u8],
        new: &[u8],
        expected_revision: u64,
        payload: &[u8],
    ) -> Result<u64> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (id, revision, cipher) = row(&transaction)?;
        let _authenticated = decrypt(old, &id, revision, &cipher)?;
        if revision as u64 != expected_revision {
            return Err(Error::Conflict);
        }
        let next = revision.checked_add(1).ok_or(Error::Invalid)?;
        let cipher = encrypt(new, &id, next, payload)?;
        transaction.execute(
            "UPDATE wallet_state SET revision=?1,ciphertext=?2 WHERE singleton=1",
            params![next, cipher],
        )?;
        transaction.commit()?;
        Ok(next as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unrelated_database_is_rejected_without_changing_its_journal_or_data() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("unrelated.sqlite");
        let database = Connection::open(&path).unwrap();
        database.execute_batch("PRAGMA journal_mode=WAL; PRAGMA user_version=99; CREATE TABLE user_data(value TEXT); INSERT INTO user_data VALUES ('preserve');").unwrap();
        assert!(matches!(Store::open(&path), Err(Error::Invalid)));
        let mode: String = database
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        let value: String = database
            .query_row("SELECT value FROM user_data", [], |r| r.get(0))
            .unwrap();
        assert_eq!(value, "preserve");
    }
    #[test]
    fn restart_conflict_password_rotation_and_no_plaintext() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wallet.sqlite");
        let mut first = Store::create(
            &path,
            b"fixture password",
            b"SECRET signing keys and private labels",
        )
        .unwrap();
        let mut second = Store::open(&path).unwrap();
        assert_eq!(second.load(b"fixture password").unwrap().revision, 0);
        assert_eq!(
            first
                .save(b"fixture password", 0, b"UPDATED private wallet state")
                .unwrap(),
            1
        );
        assert!(matches!(
            second.save(b"fixture password", 0, b"stale keys"),
            Err(Error::Conflict)
        ));
        assert!(second.save(b"wrong password", 1, b"replacement").is_err());
        drop(first);
        drop(second);
        let mut reopened = Store::open(&path).unwrap();
        assert_eq!(
            &*reopened.load(b"fixture password").unwrap().payload,
            b"UPDATED private wallet state"
        );
        assert_eq!(
            reopened
                .rotate_password(b"fixture password", b"new fixture password", 1)
                .unwrap(),
            2
        );
        assert!(reopened.load(b"fixture password").is_err());
        assert_eq!(reopened.load(b"new fixture password").unwrap().revision, 2);
        assert!(Store::create(&path, b"x", b"destroy").is_err());
        drop(reopened);
        for entry in std::fs::read_dir(directory.path()).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            assert!(!bytes.windows(6).any(|w| w == b"SECRET"));
            assert!(!bytes.windows(7).any(|w| w == b"UPDATED"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn tampered_revision_and_uncommitted_write_fail_safely() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wallet.sqlite");
        let store = Store::create(&path, b"fixture password", b"original").unwrap();
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("BEGIN IMMEDIATE; UPDATE wallet_state SET revision=1; ROLLBACK;")
            .unwrap();
        assert_eq!(store.load(b"fixture password").unwrap().revision, 0);
        connection
            .execute("UPDATE wallet_state SET revision=1", [])
            .unwrap();
        assert!(store.load(b"fixture password").is_err());
    }
}
