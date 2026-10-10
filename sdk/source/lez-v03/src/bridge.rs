// SPDX-License-Identifier: MIT OR Apache-2.0
//! In-process bridge. The generated C++ module supplies ambient dispatch context.
use crate::session::{Channel, Session};
use logos_wallet_policy::principal::Principal;
use std::{
    ffi::{CStr, CString, c_char},
    path::PathBuf,
    sync::{Mutex, OnceLock},
};
use zeroize::Zeroizing;
static SESSION: OnceLock<Mutex<Option<(PathBuf, Session)>>> = OnceLock::new();
unsafe fn input<'a>(value: *const c_char, limit: usize) -> Result<&'a str, String> {
    if value.is_null() {
        return Err("Missing native argument".into());
    }
    let bytes = unsafe { CStr::from_ptr(value) }.to_bytes();
    if bytes.len() > limit {
        return Err("Native argument exceeds size limit".into());
    }
    std::str::from_utf8(bytes).map_err(|_| "Invalid native argument encoding".into())
}
fn call(context: &str, owner: bool, body: &str, path: &str) -> Result<serde_json::Value, String> {
    let caller = Principal::from_authenticated_context(context)
        .map_err(|_| "Authenticated Basecamp caller required")?;
    let path = PathBuf::from(path);
    let mut guard = SESSION
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| "Wallet session failed; restart the module")?;
    if guard.is_none() {
        *guard = Some((
            path.clone(),
            Session::new(&path).map_err(|e| e.to_string())?,
        ));
    }
    let (saved_path, session) = guard.as_mut().ok_or("Wallet session unavailable")?;
    if saved_path != &path {
        return Err("Wallet path changed; restart the module".into());
    }
    session
        .dispatch(
            &caller,
            if owner { Channel::Owner } else { Channel::Dapp },
            body,
        )
        .map_err(|e| e.to_string())
}
/// # Safety
/// All arguments are valid NUL-terminated strings for this call. `context` must
/// come from Basecamp's authenticated ambient dispatch, never request JSON.
/// Free the result exactly once with prize_wallet_v03_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn prize_wallet_v03_call(
    context: *const c_char,
    owner: bool,
    body: *const c_char,
    path: *const c_char,
) -> *mut c_char {
    let result = std::panic::catch_unwind(|| -> Result<serde_json::Value, String> {
        let context = unsafe { input(context, 1024)? };
        let body =
            Zeroizing::new(unsafe { input(body, if owner { 16384 } else { 8192 })? }.to_owned());
        let path = unsafe { input(path, 4096)? };
        call(context, owner, &body, path)
    })
    .unwrap_or_else(|_| Err("Wallet session failed; restart the module".into()));
    let output = match result {
        Ok(value) => serde_json::json!({"ok":true,"result":value}),
        Err(error) => serde_json::json!({"ok":false,"error":error}),
    };
    CString::new(output.to_string())
        .expect("JSON escapes NUL")
        .into_raw()
}
/// # Safety
/// `value` is null or an unfreed pointer returned by prize_wallet_v03_call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn prize_wallet_v03_free(value: *mut c_char) {
    if !value.is_null() {
        drop(unsafe { CString::from_raw(value) });
    }
}
