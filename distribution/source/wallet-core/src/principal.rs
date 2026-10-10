// SPDX-License-Identifier: MIT OR Apache-2.0
//! Typed identity copied from Basecamp's authenticated dispatch context.
//! Never construct this from a dApp request body. The provider adapter supplies
//! the ambient context separately before handing work to another thread.
use crate::{AppId, Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Principal {
    /// Durable local terminal records; never accepted from Basecamp dispatch.
    LocalCli,
    Module {
        name: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        instance: String,
    },
    Derived {
        parent: String,
        leaf: String,
    },
}
impl Principal {
    /// Adapter-only: `context` comes from the authenticated transport, never
    /// from arguments supplied by the calling application. Unknown/host/operator
    /// contexts have no dApp authority and are rejected.
    pub fn from_authenticated_context(context: &str) -> Result<Self> {
        if context.len() > 1024 {
            return Err(Error::Invalid);
        }
        let principal: Self = serde_json::from_str(context).map_err(|_| Error::PermissionDenied)?;
        if matches!(principal, Self::LocalCli) {
            return Err(Error::PermissionDenied);
        }
        principal.validate()?;
        Ok(principal)
    }
    pub fn validate(&self) -> Result<()> {
        fn label(s: &str) -> bool {
            !s.trim().is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)
        }
        let valid = match self {
            Self::LocalCli => true,
            Self::Module { name, instance } => {
                label(name) && (instance.is_empty() || label(instance))
            }
            Self::Derived { parent, leaf } => label(parent) && label(leaf),
        };
        if valid { Ok(()) } else { Err(Error::Invalid) }
    }
    /// A stable, bounded policy key with no delimiter ambiguities. Preserve
    /// the full typed identity alongside this key for approval UI display.
    pub fn policy_id(&self) -> Result<AppId> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"logos.wallet.basecamp-principal.v1\0");
        let parts = match self {
            Self::LocalCli => ["local_cli", "", ""],
            Self::Module { name, instance } => ["module", name, instance],
            Self::Derived { parent, leaf } => ["derived", parent, leaf],
        };
        for part in parts {
            hash.update((part.len() as u64).to_le_bytes());
            hash.update(part.as_bytes());
        }
        Ok(AppId(format!("basecamp:v1:{:x}", hash.finalize())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_is_typed_bounded_and_not_a_request_app_name() {
        let a = Principal::from_authenticated_context(r#"{"kind":"module","name":"app"}"#).unwrap();
        let explicit_empty = Principal::from_authenticated_context(
            r#"{"kind":"module","name":"app","instance":""}"#,
        )
        .unwrap();
        assert_eq!(a.policy_id().unwrap(), explicit_empty.policy_id().unwrap());
        for context in [
            r#"{"kind":"host"}"#,
            r#"{"kind":"localcli"}"#,
            r#"{"kind":"unknown"}"#,
            r#"{"kind":"operator","name":"app"}"#,
            r#"{"kind":"module","name":"app","appId":"other"}"#,
            r#"{"kind":"module","name":""}"#,
            r#"{"kind":"derived","parent":"app"}"#,
        ] {
            assert!(Principal::from_authenticated_context(context).is_err());
        }
        for context in [
            r#"{"kind":"module","name":"other"}"#,
            r#"{"kind":"module","name":"app","instance":"one"}"#,
            r#"{"kind":"derived","parent":"app","leaf":"one"}"#,
        ] {
            assert_ne!(
                a.policy_id().unwrap(),
                Principal::from_authenticated_context(context)
                    .unwrap()
                    .policy_id()
                    .unwrap()
            );
        }
        let left = Principal::Derived {
            parent: "a:b".into(),
            leaf: "c".into(),
        };
        let right = Principal::Derived {
            parent: "a".into(),
            leaf: "b:c".into(),
        };
        assert_ne!(left.policy_id().unwrap(), right.policy_id().unwrap());
        assert!(Principal::LocalCli.validate().is_ok());
        assert_ne!(
            Principal::LocalCli.policy_id().unwrap(),
            Principal::Module {
                name: "local.wallet.cli".into(),
                instance: String::new()
            }
            .policy_id()
            .unwrap()
        );
    }
}
