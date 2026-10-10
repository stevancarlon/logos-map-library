// SPDX-License-Identifier: MIT OR Apache-2.0
//! Narrow in-process ABI for the generated native Basecamp module. No socket,
//! subprocess, stdin command protocol or secret-bearing environment variables.
use logos_wallet_lez::provider::native::{Channel, NativeSession};
use logos_wallet_policy::principal::Principal;
use std::{
    ffi::{CStr, CString, c_char},
    path::PathBuf,
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
static SESSION: OnceLock<Mutex<Option<(PathBuf, NativeSession)>>> = OnceLock::new();
// The C++ adapter owns valid NUL-terminated strings. Length bounds are checked
// before Rust parsing/allocation; pointer validity remains the C ABI contract.
unsafe fn input<'a>(value: *const c_char, limit: usize) -> Result<&'a str, String> {
    if value.is_null() {
        return Err("Missing native argument".into());
    }
    let bytes = unsafe { CStr::from_ptr(value) }.to_bytes();
    if bytes.len() > limit {
        return Err("Native request exceeds size limit".into());
    }
    std::str::from_utf8(bytes).map_err(|_| "Invalid UTF-8 request".into())
}
fn call(context: &str, owner: bool, body: &str, path: &str) -> Result<serde_json::Value, String> {
    let caller =
        Principal::from_authenticated_context(context).map_err(|error| error.to_string())?;
    let path = PathBuf::from(path);
    let mut guard = SESSION
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| "Wallet session failed; restart the module")?;
    if guard.is_none() {
        *guard = Some((path.clone(), NativeSession::new(&path)?));
    }
    let (saved_path, session) = guard.as_mut().ok_or("Wallet session unavailable")?;
    if saved_path != &path {
        return Err("Wallet path changed; restart the module".into());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "System clock is invalid")?
        .as_secs();
    session.dispatch(
        &caller,
        if owner { Channel::Owner } else { Channel::Dapp },
        body,
        now,
    )
}
/// # Safety
/// All input pointers must be valid NUL-terminated strings for the duration of
/// the call. Context must come from Basecamp ambient dispatch, not request JSON.
/// The returned pointer must be freed exactly once with prize_wallet_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn prize_wallet_call(
    context: *const c_char,
    owner: bool,
    body: *const c_char,
    path: *const c_char,
) -> *mut c_char {
    let result = std::panic::catch_unwind(|| -> Result<serde_json::Value, String> {
        let context = unsafe { input(context, 1024)? };
        let body = Zeroizing::new(unsafe { input(body, 16384)? }.to_owned());
        let path = unsafe { input(path, 4096)? };
        call(context, owner, &body, path)
    })
    .unwrap_or_else(|_| Err("Wallet session failed; restart the module".into()));
    let output = match result {
        Ok(value) => serde_json::json!({"ok":true,"result":value}),
        Err(message) => serde_json::json!({"ok":false,"error":message}),
    };
    CString::new(output.to_string())
        .expect("JSON escapes NUL")
        .into_raw()
}
/// # Safety
/// `value` must be null or a live pointer returned by prize_wallet_call, and
/// must not be used or freed again after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn prize_wallet_free(value: *mut c_char) {
    if !value.is_null() {
        drop(unsafe { CString::from_raw(value) });
    }
}
