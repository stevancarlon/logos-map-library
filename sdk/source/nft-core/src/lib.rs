// SPDX-License-Identifier: MIT OR Apache-2.0
//! NFT inventory projection using the reference token program's real Borsh types.
//! These records never serve as cryptographic ownership proofs.
use logos_wallet_policy::{AppId, Policy, Scope};
use serde::Serialize;
use spel_framework::prelude::{Account, AccountId, ProgramId};
use std::collections::BTreeMap;
use token_core::TokenHolding;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("NFT enumeration requires explicit permission for this account")]
    Permission,
    #[error("Token holding data is invalid")]
    Data,
    #[error("Token account belongs to a different program")]
    Owner,
    #[error("Metadata fetching from this source is disabled")]
    ExternalDisabled,
    #[error("Invalid metadata URI")]
    Uri,
}
#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum Kind {
    Master { remaining_prints: u128 },
    PrintedCopy,
}
#[derive(Debug, Clone, Serialize)]
pub struct Nft {
    /// Current holding account; NOT claimed to be a stable token ID across transfers.
    pub holding_id: AccountId,
    pub definition_id: AccountId,
    pub kind: Kind,
    pub visibility: Visibility,
    pub metadata: MetadataState,
}
#[derive(Debug, Clone, Copy, Serialize)]
pub enum Visibility {
    Public,
    Private,
}
#[derive(Debug, Clone, Serialize)]
pub enum MetadataState {
    NotFetched,
    Unavailable { reason: String },
    Available { name: String, image: Option<String> },
}
pub struct Snapshot {
    pub holding_id: AccountId,
    pub account: Account,
    pub visibility: Visibility,
}
/// The trusted wallet must supply snapshots belonging to the selected owner.
/// Reading its private state and proving this association is the wallet adapter's job.
pub fn enumerate(
    policy: &Policy,
    app: &AppId,
    owner: [u8; 32],
    token_program: ProgramId,
    snapshots: &[Snapshot],
) -> Result<Vec<Nft>, Error> {
    if !policy.permitted(app, Scope::NftEnumeration, Some(owner)) {
        return Err(Error::Permission);
    }
    let mut result = Vec::new();
    for s in snapshots {
        if s.account.program_owner != token_program {
            return Err(Error::Owner);
        }
        let holding = TokenHolding::try_from(&s.account.data).map_err(|_| Error::Data)?;
        let (definition_id, kind) = match holding {
            TokenHolding::Fungible { .. } => continue,
            TokenHolding::NftMaster {
                definition_id,
                print_balance,
            } if print_balance > 0 => (
                definition_id,
                Kind::Master {
                    remaining_prints: print_balance - 1,
                },
            ),
            TokenHolding::NftPrintedCopy {
                definition_id,
                owned: true,
            } => (definition_id, Kind::PrintedCopy),
            _ => continue,
        };
        result.push(Nft {
            holding_id: s.holding_id,
            definition_id,
            kind,
            visibility: s.visibility,
            metadata: MetadataState::NotFetched,
        });
    }
    Ok(result)
}
pub fn collections(nfts: &[Nft]) -> BTreeMap<String, Vec<&Nft>> {
    let mut map = BTreeMap::new();
    for nft in nfts {
        map.entry(nft.definition_id.to_string())
            .or_insert_with(Vec::new)
            .push(nft);
    }
    map
}
#[derive(Debug, PartialEq)]
pub enum FetchTarget {
    LogosStorage(String),
    OptedInHttps(String),
}
/// Pure routing decision. Both public and private holdings default to no central fetch.
/// The caller must separately enforce media size, content-type and timeout limits.
pub fn metadata_target(uri: &str, allow_central: bool) -> Result<FetchTarget, Error> {
    if let Some(cid) = uri.strip_prefix("storage://") {
        if cid.is_empty() || cid.len() > 128 || !cid.bytes().all(|c| c.is_ascii_alphanumeric()) {
            return Err(Error::Uri);
        }
        return Ok(FetchTarget::LogosStorage(cid.into()));
    }
    let u = url::Url::parse(uri).map_err(|_| Error::Uri)?;
    if u.scheme() != "https" || !u.username().is_empty() || u.password().is_some() {
        return Err(Error::Uri);
    }
    if !allow_central {
        return Err(Error::ExternalDisabled);
    }
    Ok(FetchTarget::OptedInHttps(u.to_string()))
}
#[cfg(test)]
mod tests {
    use super::*;
    use logos_wallet_policy::Grant;
    use std::collections::BTreeSet;
    fn app() -> AppId {
        AppId("fixture".into())
    }
    fn snap(holding: TokenHolding) -> Snapshot {
        let account = Account {
            program_owner: [9; 8],
            data: (&holding).into(),
            ..Account::default()
        };
        Snapshot {
            holding_id: AccountId::new([2; 32]),
            account,
            visibility: Visibility::Private,
        }
    }
    fn policy(scope: Scope) -> Policy {
        let mut p = Policy::default();
        p.set_grant(
            app(),
            Grant {
                accounts: BTreeSet::from([[1; 32]]),
                scopes: BTreeSet::from([scope]),
            },
        )
        .unwrap();
        p
    }
    #[test]
    fn proof_permission_cannot_enumerate() {
        assert!(
            enumerate(
                &policy(Scope::CollectionProof),
                &app(),
                [1; 32],
                [9; 8],
                &[]
            )
            .is_err()
        );
    }
    #[test]
    fn zeroed_and_fungible_holdings_are_excluded() {
        let def = AccountId::new([3; 32]);
        let snapshots = vec![
            snap(TokenHolding::NftMaster {
                definition_id: def,
                print_balance: 0,
            }),
            snap(TokenHolding::NftPrintedCopy {
                definition_id: def,
                owned: false,
            }),
            snap(TokenHolding::Fungible {
                definition_id: def,
                balance: 100,
            }),
            snap(TokenHolding::NftMaster {
                definition_id: def,
                print_balance: 1,
            }),
            snap(TokenHolding::NftPrintedCopy {
                definition_id: def,
                owned: true,
            }),
        ];
        let nfts = enumerate(
            &policy(Scope::NftEnumeration),
            &app(),
            [1; 32],
            [9; 8],
            &snapshots,
        )
        .unwrap();
        assert_eq!(nfts.len(), 2);
        assert_eq!(
            nfts[0].kind,
            Kind::Master {
                remaining_prints: 0
            }
        );
        assert_eq!(collections(&nfts).len(), 1);
        assert!(matches!(nfts[1].metadata, MetadataState::NotFetched));
    }
    #[test]
    fn central_fetch_is_opt_in_and_local_storage_allowed() {
        assert!(matches!(
            metadata_target("https://example.com/nft.json", false),
            Err(Error::ExternalDisabled)
        ));
        assert!(metadata_target("https://example.com/nft.json", true).is_ok());
        assert!(matches!(
            metadata_target("storage://bafyFixture", false),
            Ok(FetchTarget::LogosStorage(_))
        ));
        assert!(metadata_target("file:///etc/passwd", true).is_err());
    }
}
