// SPDX-License-Identifier: MIT OR Apache-2.0
//! Read-only JSON/C ABI for a standalone Basecamp SDK module. No file or signing APIs.
use crate::rpc::Node;
use crate::{Filter, Registry};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    ffi::{CStr, CString, c_char},
    str::FromStr,
};

#[derive(Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Catalog {},
    #[cfg(feature = "distribution")]
    Discover {},
    #[cfg(feature = "distribution")]
    LatestVersion {
        region: String,
    },
    Query {
        rpc: String,
        program: String,
        page: u64,
        filter: QueryFilter,
    },
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum QueryFilter {
    All {},
    Region { value: String },
    Parent { value: String },
    Cid { value: String },
    Registrant { value: String },
}
/// Caller-selected network reads only; catalog is bundled and requires no network.
/// Hosting assertions in query results are not checksummed downloads or availability proofs.
pub fn request(body: &str) -> std::result::Result<Value, String> {
    if body.len() > 8192 || body.contains('\0') {
        return Err("Map request exceeds limits".into());
    }
    let request: Request = serde_json::from_str(body).map_err(|_| "Invalid map SDK request")?;
    match request {
        Request::Catalog {} => {
            let mut value: Value =
                serde_json::from_str(include_str!("../../../maps/data/catalog.json"))
                    .map_err(|_| "Bundled catalog is invalid")?;
            value["registry_protocol"] = json!("lez-v0.3");
            Ok(value)
        }
        #[cfg(feature = "distribution")]
        Request::Discover {} => {
            serde_json::to_value(crate::distribution::fetch_catalog().map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())
        }
        #[cfg(feature = "distribution")]
        Request::LatestVersion { region } => {
            let region = crate::distribution::importer::supported_region(&region)
                .map_err(|e| e.to_string())?;
            serde_json::to_value(
                crate::distribution::latest_version(&region).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())
        }
        Request::Query {
            rpc,
            program,
            page,
            filter,
        } => {
            // Validate every field before initiating a request.
            if page.checked_mul(crate::PAGE_SIZE as u64).is_none() {
                return Err("Map page overflow".into());
            }
            let program = lee_v03::AccountId::from_str(&program)
                .map_err(|_| "Expected a v0.3 registry account address")?;
            let value = match &filter {
                QueryFilter::All {} => None,
                QueryFilter::Region { value }
                | QueryFilter::Parent { value }
                | QueryFilter::Cid { value }
                | QueryFilter::Registrant { value } => Some(value.as_str()),
            };
            if value
                .is_some_and(|v| v.is_empty() || v.len() > 256 || v.chars().any(char::is_control))
            {
                return Err("Invalid map filter value".into());
            }
            let registrant = if let QueryFilter::Registrant { value } = &filter {
                Some(
                    lee_v03::AccountId::from_str(value)
                        .map_err(|_| "Invalid registrant account")?,
                )
            } else {
                None
            };
            let filter = Filter {
                region: matches!(filter, QueryFilter::Region { .. })
                    .then_some(value)
                    .flatten(),
                parent: matches!(filter, QueryFilter::Parent { .. })
                    .then_some(value)
                    .flatten(),
                cid: matches!(filter, QueryFilter::Cid { .. })
                    .then_some(value)
                    .flatten(),
                registrant: registrant.as_ref().map(|id| id.value()),
            };
            let registry = Registry {
                reader: Node::new(&rpc).map_err(|e| e.to_string())?,
                program,
            };
            serde_json::to_value(registry.query(page, &filter).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())
        }
    }
}
/// # Safety
/// `body` must be a valid NUL-terminated string, or null. Free the returned
/// allocation exactly once with `prize_maps_free`; do not modify it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn prize_maps_request(body: *const c_char) -> *mut c_char {
    let result = std::panic::catch_unwind(|| {
        if body.is_null() {
            return Err("Missing map request".to_owned());
        }
        let bytes = unsafe { CStr::from_ptr(body) }.to_bytes();
        if bytes.len() > 8192 {
            return Err("Map request exceeds limits".into());
        }
        request(std::str::from_utf8(bytes).map_err(|_| "Invalid UTF-8 map request")?)
    })
    .unwrap_or_else(|_| Err("Map SDK request failed".into()));
    let envelope = match result {
        Ok(value) => json!({"ok":true,"result":value}),
        Err(error) => json!({"ok":false,"error":error}),
    };
    CString::new(envelope.to_string())
        .expect("JSON escapes NUL")
        .into_raw()
}
/// # Safety
/// The pointer must be null or an unfreed result from `prize_maps_request`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn prize_maps_free(value: *mut c_char) {
    if !value.is_null() {
        drop(unsafe { CString::from_raw(value) });
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog_is_available_without_network_or_distribution_application() {
        let value = request(r#"{"method":"catalog"}"#).unwrap();
        assert_eq!(value["canonical_regions"].as_array().unwrap().len(), 72);
        assert_eq!(value["missing"], json!([]));
    }
    #[test]
    fn public_discovery_rejects_invalid_paths_and_extra_fields_before_network() {
        assert!(request(r#"{"method":"latest_version","region":"../../private"}"#).is_err());
        assert!(request(r#"{"method":"discover","url":"https://example.invalid"}"#).is_err());
    }
    #[cfg(not(feature = "distribution"))]
    #[test]
    fn standalone_build_has_no_live_source_discovery() {
        assert!(request(r#"{"method":"discover"}"#).is_err());
        assert!(request(r#"{"method":"latest_version","region":"africa/ethiopia"}"#).is_err());
    }
    #[test]
    fn native_boundary_has_no_signing_or_file_operations() {
        for value in [
            r#"{"method":"upload","path":"/tmp/file"}"#,
            r#"{"method":"register"}"#,
            r#"{"method":"catalog","rpc":"http://127.0.0.1:1"}"#,
        ] {
            assert!(request(value).is_err());
        }
        let input = CString::new("not JSON").unwrap();
        unsafe {
            let result = prize_maps_request(input.as_ptr());
            let value: Value = serde_json::from_slice(CStr::from_ptr(result).to_bytes()).unwrap();
            assert_eq!(value["ok"], false);
            prize_maps_free(result);
            let null = prize_maps_request(std::ptr::null());
            let value: Value = serde_json::from_slice(CStr::from_ptr(null).to_bytes()).unwrap();
            assert_eq!(value["ok"], false);
            prize_maps_free(null);
        }
    }
}
