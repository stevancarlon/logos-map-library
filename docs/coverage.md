# Public coverage verification

Registry announcements alone do not satisfy LP-0018 coverage. Each counted
region needs retrievable Storage bytes matching the dated Geofabrik MD5. The
submission needs at least 25 distinct regions spanning at least 15 countries.
Multiple versions or mirrors of one region count once; subregions of a decomposed
country contribute to that same country.

After deploying and populating the official registry, run the read-only evaluator:

```sh
python3 integration/scripts/verify-maps-coverage.py \
  --cli /path/to/installed/logos_maps/bin/maps-v03 \
  --program "$DEPLOYED_REGISTRY_ACCOUNT" \
  --storage "$PERSISTENT_STORAGE_API" \
  --scratch /path/to/disposable-download-space \
  --output /path/to/new-coverage-evidence.json
```

The default RPC is `https://testnet.lez.logos.co`. A different endpoint can be
tested with `--rpc`, but its report cannot claim the official coverage threshold.
No default registry address is provided: deployment is still outstanding.

The tool scans bounded registry pages, rejects a changed or incomplete scan,
validates canonical hierarchy and source dates, fetches each candidate's dated
Geofabrik checksum, downloads the Storage file through the published SDK CLI,
and independently computes MD5, SHA-256 and byte length. It checks the canonical
checksum again after downloading. Each temporary file is removed before moving
to the next candidate. Failed entries are recorded and do not count. A valid
older snapshot can qualify if a newer announcement fails verification.

Defaults limit each download to 2 GiB, attempted downloads to 10 GiB total and
the registry scan to 64 pages. Adjust `--max-file-bytes`, `--max-total-bytes` and
`--max-pages` explicitly for larger datasets. The scratch location must have room
for one full file; reports are checkpointed, and existing output files are refused.
The tool does not modify registry state or upload data.

Exit status zero requires a completed scan on the official endpoint and both
coverage thresholds. Exit status one can mean insufficient coverage or a failed
check; inspect `result`, `error`, `failed`, and `coverage` in the report. Even a
qualifying report only observes availability at that time. Keep the Storage node
running and retain the registry account, CIDs and report for evaluator rechecks.
Independent ecosystem adoption remains a separate mandatory requirement.
