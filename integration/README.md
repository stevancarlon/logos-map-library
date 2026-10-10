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
