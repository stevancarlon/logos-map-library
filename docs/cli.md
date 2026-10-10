# Map Library CLI

This is a development release. No official-testnet map registry address has been
published. Use an initialized registry you control and its executable account
ID, not its RISC0 image ID. Local integration results do not establish public
hosting or independent adoption.

## Build both clients

From this repository's root, with Rust 1.98.1, a C compiler, pkg-config and OpenSSL
development headers available:

```sh
cd sdk/source
export CARGO_TARGET_DIR="$PWD/target"
cargo build --manifest-path lez-v03/Cargo.toml --locked \
  -p logos-maps-v03-sdk --bin maps-v03
cargo build --manifest-path lez-v03/Cargo.toml --locked \
  -p logos-maps-v03-publisher --features hosting --bin maps-publish
export PATH="$PWD/target/debug:$PATH"
```

`maps-v03` reads metadata and moves verified files. `maps-publish` owns the
signing boundary and requires an interactive terminal for passwords and exact
transaction approvals. The published Basecamp app includes `maps-v03`; build
`maps-publish` from source using the command above for combined terminal hosting.

## Configure and create local signing state

In the examples below, set `RPC`, `PROGRAM` and `STORAGE_API` to your chosen
sequencer, deployed executable account and Storage API. A Storage API normally
ends in `/api/storage/v1`. `GAS_LIMIT`, `MAX_FEE` and `TIP` are your explicit
transaction limits; review the current network fee quote and every approval.
No public-testnet funding or registry deployment is performed by these examples.

```sh
umask 077
mkdir -p map-state downloads
maps-publish key-create "$PWD/map-state/key.vault"
maps-publish outbox-create "$PWD/map-state/outbox.sqlite"
```

Fund the displayed public account on the configured network. Keep the vault,
SQLite outbox, their passwords and saved upload receipts. Commands refuse to
overwrite existing state. Passwords are entered through hidden terminal prompts.

## Discover and choose a dated snapshot

```sh
maps-v03 catalog
maps-v03 latest-version africa/ethiopia
maps-v03 discover-versions
```

`catalog` uses the embedded 72-region partition. The other commands contact
Geofabrik. Use the returned numeric `version` as `YYYYMMDD` below. A missing or
unavailable source date is an error, not evidence that a registry-hosted map is
unavailable.

## Fetch, store and register; or import a local file

```text
maps-publish host-fetch RPC PROGRAM STORAGE_API REGION YYYYMMDD NEW_PBF MAX_BYTES NEW_RECEIPT KEY_VAULT SQLITE GAS_LIMIT MAX_FEE TIP
maps-publish host-local RPC PROGRAM STORAGE_API REGION YYYYMMDD EXISTING_PBF MAX_BYTES NEW_RECEIPT KEY_VAULT SQLITE GAS_LIMIT MAX_FEE TIP
```

Substitute your values for the uppercase arguments. Local import verifies the
file against the dated Geofabrik MD5. Both commands store a verified snapshot,
save its receipt, and request a separate approval for each needed registration
transaction. Uploads are public even when you cancel the later signing review.
An initialized registry is required; the planner can create missing registry
pages. A source download must use a new destination, and a new hosting job must
use a new receipt filename.

For bulk hosting, write an `items.json` array using this schema. Replace the
example dates and destination paths with your selected snapshots and new paths:

```json
[
  {"region":"africa/ethiopia","version":20261009,"selected":true,
   "input":{"kind":"fetch","destination":"/absolute/new/ethiopia.osm.pbf"}},
  {"region":"africa/kenya","version":20261009,"selected":true,
   "input":{"kind":"local","path":"/absolute/existing/kenya.osm.pbf"}},
  {"region":"africa/egypt","version":20261009,"selected":false,
   "input":{"kind":"fetch","destination":"/absolute/new/egypt.osm.pbf"}}
]
```

```text
maps-publish host-bulk RPC PROGRAM STORAGE_API ITEMS_JSON_FILE MAX_BYTES NEW_RECEIPT KEY_VAULT SQLITE GAS_LIMIT MAX_FEE TIP
```

Unselected regions are skipped. The closed partition excludes overlapping
parent extracts. A partially successful batch reports each outcome and leaves
`complete` false when any selected region failed. Retry failed regions separately
with a new receipt; do not silently treat a stored subset as a complete batch.

## Resume or batch-register already stored snapshots

```text
maps-publish publish-all RPC PROGRAM KEY_VAULT SQLITE RECEIPT_JSON GAS_LIMIT MAX_FEE TIP
maps-publish register RPC PROGRAM KEY_VAULT SQLITE SNAPSHOTS_JSON_FILE GAS_LIMIT MAX_FEE TIP
maps-publish history SQLITE
maps-publish reconcile RPC SQLITE TRANSACTION_HASH
```

`publish-all` resumes a saved JSON-array receipt without uploading again and
plans page-sized transactions. `register` submits 1–8 verified stored snapshots
that fit the current page. Do not construct hosting assertions for files you
have not stored. Completion is checked against matching registry records.
Uncertain submissions stop rather than being blindly retried; retain the outbox
and reconcile the existing hash first.

## Lookup, update checks and download

```text
maps-v03 registry-page RPC PROGRAM PAGE region REGION_PATH
maps-v03 registry-page RPC PROGRAM PAGE parent PARENT_PATH
maps-v03 registry-page RPC PROGRAM PAGE cid CID
maps-v03 updates RPC PROGRAM '["africa/ethiopia"]' MAX_PAGES
maps-v03 download-snapshot STORAGE_API SNAPSHOT_JSON MAX_BYTES NEW_DESTINATION
maps-v03 fetch-region REGION_PATH NEW_DESTINATION MAX_BYTES
```

Take `REGION_PATH` and `PARENT_PATH` from `catalog`. Lookup returns a `records`
array and `next_page`; follow pagination rather than assuming page zero holds
the newest entry globally. For `download-snapshot`, pass one record's complete
`snapshot` object as a single quoted JSON argument. The download checks its
SHA-256, MD5 and exact byte count before publishing the destination file.
Registry metadata alone is an unverified hosting assertion.

Hosted lookup and download use your configured nodes and do not contact
Geofabrik. Update checks intentionally compare the canonical source date.
`fetch-region` is the explicit Geofabrik fallback; it does not register or host
the downloaded file. Existing destination files are never overwritten.
