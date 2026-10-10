# Packaged Basecamp runtime fixture

Runs the actual app in a disposable Basecamp profile: shared catalog, Rust CLI
checksum verification, loopback Storage download, and corruption rejection.
It installs only provided verified LGX packages. It does not establish real
Storage availability, registry deployment, independent adoption or full
end-to-end hosting. `native/` contains source copies used for evidence hashes.

Create `artifacts/` and `evidence/`, set `MAPS_RELEASE_APP_LGX`,
`MAPS_RELEASE_PUBLISHER_LGX`, `MAPS_RELEASE_DISTRIBUTION_LGX` and
`MAPS_RELEASE_LGX`, then run `python3 scripts/test-basecamp-maps.py
--basecamp /path/to/BasecampExecutable`. The installer detects Linux x86_64
or macOS Apple Silicon and refuses existing module destinations.

## Real nodes and authentic extracts

The real integration sources use the same pinned `sdk/source` Rust workspace.
Copy the scripts into its `scripts/` directory and the evidence-only `native/`
source copies alongside that workspace. Build the map guest, `maps-chain` and
`native-publisher-fixture` examples, then use `test-maps-v03-host.py`.
`--mode fetch --version YYYYMMDD` exercises a real dated Ethiopia extract through
an isolated Storage node and standalone sequencer. No pre-existing local file
is required. The `--bulk-fetch-ui --basecamp PATH` variant instead exercises
Basecamp form handlers for Ethiopia and Kenya, excludes Egypt, signs and
registers the batch, checks downloads and restarts Basecamp for reconciliation.
Both variants create disposable local fixture keys; never use them publicly.
The UI variant supports verified published LGX packages through the environment
variables above. Passing a fixture does not establish public hosting, official
testnet deployment or independent adoption.
