// SPDX-License-Identifier: MIT OR Apache-2.0
//! Owner-only Basecamp bridge. Ambient identity is supplied by generated native glue.
use crate::{Proposal, Publisher, prepare};
use lee_core_v03::account::AccountId;
use lee_v03::{PrivateKey, PublicKey, fees::FeeDeclaration};
use logos_maps_v03_sdk::{Instruction, Registry, Snapshot, rpc::Node};
use logos_wallet_policy::{principal::Principal, vault};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use std::{
    ffi::{CStr, CString, c_char},
    path::Path,
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, String>;
fn secret<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Status {},
    Lock {},
    Unlock {
        rpc: String,
        program: String,
        key_path: String,
        outbox_path: String,
        #[serde(deserialize_with = "secret")]
        key_password: Zeroizing<String>,
        #[serde(deserialize_with = "secret")]
        outbox_password: Zeroizing<String>,
    },
    Review {
        instruction: Instruction,
        gas_limit: String,
        max_fee: String,
        tip: String,
    },
    Register {
        snapshots: Vec<Snapshot>,
        gas_limit: String,
        max_fee: String,
        tip: String,
    },
    NextRegistration {
        snapshots: Vec<Snapshot>,
        gas_limit: String,
        max_fee: String,
        tip: String,
    },
    Approve {
        digest: String,
    },
    Cancel {},
    History {},
    Reconcile {
        hash: String,
    },
}
struct Unlocked {
    registry: Registry<Node>,
    key: PrivateKey,
    publisher: Publisher,
    password: Zeroizing<String>,
    pending: Option<Proposal>,
    touched: u64,
}
#[derive(Default)]
pub struct Session {
    unlocked: Option<Unlocked>,
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "Clock unavailable".into())
        .map(|v| v.as_millis() as u64)
}
fn visible(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.remove("transaction");
        object.remove("message_borsh_hex");
        if let Some(raw) = object
            .get("instruction")
            .and_then(|v| v.pointer("/RegisterBatch/snapshots_json"))
            .and_then(Value::as_str)
            && let Ok(snapshots) = serde_json::from_str::<Value>(raw)
        {
            object.insert("snapshots".into(), snapshots);
        }
    } else if let Some(rows) = value.as_array_mut() {
        for row in rows {
            *row = visible(row.take());
        }
    }
    value
}
impl Session {
    /// `context` MUST be copied from Basecamp's authenticated ambient caller,
    /// never from request JSON. Unknown/derived/other modules are denied first.
    pub fn dispatch(&mut self, context: &str, body: &str) -> Result<Value> {
        let principal = Principal::from_authenticated_context(context)
            .map_err(|_| "Authenticated map app required")?;
        if !matches!(principal,Principal::Module {ref name,ref instance} if name=="logos_maps" && instance.is_empty())
        {
            return Err("Only the authenticated Map Library owner may use this endpoint".into());
        }
        if body.len() > 65536 {
            return Err("Request exceeds limit".into());
        }
        let time = now()?;
        if self
            .unlocked
            .as_ref()
            .is_some_and(|s| time.saturating_sub(s.touched) > 300_000)
        {
            self.unlocked = None;
        }
        let request: Request =
            serde_json::from_str(body).map_err(|_| "Invalid publisher request")?;
        match request {
            Request::Status {} => {
                return Ok(
                    json!({"unlocked":self.unlocked.is_some(),"review_pending":self.unlocked.as_ref().is_some_and(|s|s.pending.is_some())}),
                );
            }
            Request::Lock {} => {
                self.unlocked = None;
                return Ok(json!({"unlocked":false}));
            }
            Request::Unlock {
                rpc,
                program,
                key_path,
                outbox_path,
                key_password,
                outbox_password,
            } => {
                self.unlocked = None;
                if !Path::new(&key_path).is_absolute() || !Path::new(&outbox_path).is_absolute() {
                    return Err("Use absolute key and outbox paths".into());
                }
                let payload = vault::read_file(Path::new(&key_path), key_password.as_bytes())
                    .map_err(|e| e.to_string())?;
                if payload.len() != 40 || &payload[..8] != b"REGKEY01" {
                    return Err("Not a registry signing-key vault".into());
                }
                let seed = Zeroizing::new(
                    <[u8; 32]>::try_from(&payload[8..]).map_err(|_| "Invalid signing key")?,
                );
                let key = PrivateKey::try_new(*seed).map_err(|_| "Invalid signing key")?;
                let publisher =
                    Publisher::open(Path::new(&outbox_path)).map_err(|e| e.to_string())?;
                publisher
                    .submissions(outbox_password.as_bytes())
                    .map_err(|e| e.to_string())?;
                let author = AccountId::from(&PublicKey::new_from_private_key(&key));
                let registry = Registry {
                    reader: Node::new(&rpc).map_err(|e| e.to_string())?,
                    program: program.parse().map_err(|_| "Invalid registry account")?,
                };
                self.unlocked = Some(Unlocked {
                    registry,
                    key,
                    publisher,
                    password: outbox_password,
                    pending: None,
                    touched: time,
                });
                return Ok(json!({"unlocked":true,"author":author.to_string()}));
            }
            _ => {}
        }
        let session = self
            .unlocked
            .as_mut()
            .ok_or("Unlock the map publisher first")?;
        session.touched = time;
        let author = AccountId::from(&PublicKey::new_from_private_key(&session.key));
        let proposal = match request {
            Request::Review {
                instruction,
                gas_limit,
                max_fee,
                tip,
            } => Some((instruction, gas_limit, max_fee, tip)),
            Request::Register {
                snapshots,
                gas_limit,
                max_fee,
                tip,
            } => {
                session.pending = None;
                if snapshots.is_empty() || snapshots.len() > 8 {
                    return Err("Select one to eight stored snapshots".into());
                }
                let count = session.registry.catalog().map_err(|e| e.to_string())?.count;
                Some((
                    Instruction::RegisterBatch {
                        number: count / 64,
                        expected_count: count,
                        timestamp: time,
                        snapshots_json: serde_json::to_string(&snapshots)
                            .map_err(|_| "Invalid snapshots")?,
                    },
                    gas_limit,
                    max_fee,
                    tip,
                ))
            }
            Request::NextRegistration {
                snapshots,
                gas_limit,
                max_fee,
                tip,
            } => {
                session.pending = None;
                match session
                    .registry
                    .next_registration(author, &snapshots, time, 4096)
                    .map_err(|e| e.to_string())?
                {
                    Some(instruction) => Some((instruction, gas_limit, max_fee, tip)),
                    None => {
                        return Ok(
                            json!({"complete":true,"verification":"matching_registry_records_by_author"}),
                        );
                    }
                }
            }
            Request::Cancel {} => {
                session.pending = None;
                return Ok(json!({"status":"canceled","submitted":false}));
            }
            Request::Approve { digest } => {
                let proposal = session.pending.take().ok_or("No pending review")?;
                if proposal.review().digest != digest {
                    return Err("Review digest mismatch; prepare again".into());
                }
                let row = session
                    .publisher
                    .approve(
                        session.password.as_bytes(),
                        &session.registry,
                        proposal,
                        &session.key,
                        time,
                    )
                    .map_err(|e| e.to_string())?;
                return serde_json::to_value(row)
                    .map(visible)
                    .map_err(|_| "Response encoding".into());
            }
            Request::History {} => {
                return serde_json::to_value(
                    session
                        .publisher
                        .submissions(session.password.as_bytes())
                        .map_err(|e| e.to_string())?,
                )
                .map(visible)
                .map_err(|_| "Response encoding".into());
            }
            Request::Reconcile { hash } => {
                return serde_json::to_value(
                    session
                        .publisher
                        .reconcile(session.password.as_bytes(), &session.registry.reader, &hash)
                        .map_err(|e| e.to_string())?,
                )
                .map(visible)
                .map_err(|_| "Response encoding".into());
            }
            _ => None,
        };
        if let Some((instruction, gas, cap, tip)) = proposal {
            session.pending = None;
            let fee = FeeDeclaration::new(
                author,
                gas.parse().map_err(|_| "Invalid gas limit")?,
                tip.parse().map_err(|_| "Invalid tip")?,
                cap.parse().map_err(|_| "Invalid fee cap")?,
            );
            let proposal = prepare(&session.registry, author, instruction, fee, time)
                .map_err(|e| e.to_string())?;
            let review = serde_json::to_value(proposal.review())
                .map(visible)
                .map_err(|_| "Response encoding")?;
            session.pending = Some(proposal);
            Ok(review)
        } else {
            Err("Unsupported publisher operation".into())
        }
    }
}
static SESSION: OnceLock<Mutex<Session>> = OnceLock::new();
unsafe fn input<'a>(p: *const c_char, limit: usize) -> Result<&'a str> {
    if p.is_null() {
        return Err("Missing native argument".into());
    }
    let bytes = unsafe { CStr::from_ptr(p) }.to_bytes();
    if bytes.len() > limit {
        return Err("Native argument exceeds limit".into());
    }
    std::str::from_utf8(bytes).map_err(|_| "Invalid native encoding".into())
}
/// # Safety
/// Both pointers are live NUL-terminated strings. Context is authenticated
/// ambient identity, not user JSON. Free the result once with maps_publisher_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn maps_publisher_call(
    context: *const c_char,
    body: *const c_char,
) -> *mut c_char {
    let result = std::panic::catch_unwind(|| -> Result<Value> {
        let context = unsafe { input(context, 1024)? };
        let body = Zeroizing::new(unsafe { input(body, 65536)? }.to_owned());
        SESSION
            .get_or_init(|| Mutex::new(Session::default()))
            .lock()
            .map_err(|_| "Publisher failed; restart module")?
            .dispatch(context, &body)
    })
    .unwrap_or_else(|_| Err("Publisher failed; restart module".into()));
    let response = match result {
        Ok(value) => json!({"ok":true,"result":value}),
        Err(error) => json!({"ok":false,"error":error}),
    };
    CString::new(response.to_string())
        .expect("JSON escapes NUL")
        .into_raw()
}
/// # Safety
/// Pointer is null or an unfreed result from maps_publisher_call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn maps_publisher_free(p: *mut c_char) {
    if !p.is_null() {
        drop(unsafe { CString::from_raw(p) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const OWNER: &str = r#"{"kind":"module","name":"logos_maps","instance":""}"#;
    #[test]
    fn other_callers_cannot_use_even_status_or_lock() {
        let mut session = Session::default();
        for context in [
            r#"{"kind":"module","name":"prize_maps_consumer","instance":""}"#,
            r#"{"kind":"module","name":"logos_maps","instance":"other"}"#,
            r#"{"kind":"derived","parent":"logos_maps","leaf":"x"}"#,
            "{}",
        ] {
            for body in [
                r#"{"op":"status"}"#,
                r#"{"op":"lock"}"#,
                r#"{"op":"approve","digest":"x"}"#,
            ] {
                assert!(session.dispatch(context, body).is_err());
            }
        }
        assert_eq!(
            session.dispatch(OWNER, r#"{"op":"status"}"#).unwrap()["unlocked"],
            false
        );
    }
    #[test]
    fn unlocked_session_is_owner_scoped_and_idle_expiry_clears_it() {
        let directory = tempfile::tempdir().unwrap();
        let key = directory.path().join("key.vault");
        let outbox = directory.path().join("outbox.sqlite");
        let mut payload = Zeroizing::new(Vec::from(b"REGKEY01".as_slice()));
        payload.extend_from_slice(&[1; 32]);
        vault::create_file(&key, b"fixture", &payload).unwrap();
        Publisher::create(&outbox, b"fixture").unwrap();
        let mut session = Session::default();
        let unlock = json!({"op":"unlock","rpc":"http://127.0.0.1:1", "program":AccountId::new([3;32]).to_string(),
            "key_path":key,"outbox_path":outbox,"key_password":"fixture","outbox_password":"fixture"}).to_string();
        assert_eq!(session.dispatch(OWNER, &unlock).unwrap()["unlocked"], true);
        let other = r#"{"kind":"module","name":"intruder","instance":""}"#;
        assert!(session.dispatch(other, r#"{"op":"lock"}"#).is_err());
        assert_eq!(
            session.dispatch(OWNER, r#"{"op":"status"}"#).unwrap()["unlocked"],
            true
        );
        session.unlocked.as_mut().unwrap().touched = now().unwrap() - 300_001;
        assert_eq!(
            session.dispatch(OWNER, r#"{"op":"status"}"#).unwrap()["unlocked"],
            false
        );
        assert_eq!(session.dispatch(OWNER, &unlock).unwrap()["unlocked"], true);
        let mut bad: Value = serde_json::from_str(&unlock).unwrap();
        bad["key_password"] = json!("wrong");
        assert!(session.dispatch(OWNER, &bad.to_string()).is_err());
        assert_eq!(
            session.dispatch(OWNER, r#"{"op":"status"}"#).unwrap()["unlocked"],
            false
        );
    }

    #[test]
    fn locked_session_rejects_approval_and_request_context_spoofing() {
        let mut session = Session::default();
        assert!(
            session
                .dispatch(OWNER, r#"{"op":"approve","digest":"x"}"#)
                .is_err()
        );
        assert!(
            session
                .dispatch(OWNER, r#"{"op":"status","caller":"logos_maps"}"#)
                .is_err()
        );
        assert!(session.dispatch(OWNER, &" ".repeat(65537)).is_err());
        assert_eq!(
            session.dispatch(OWNER, r#"{"op":"lock"}"#).unwrap()["unlocked"],
            false
        );
    }
}
