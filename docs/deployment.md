# Registry deployment — not yet performed on the official zone

Download the [undeployed registry artifact](https://github.com/stevancarlon/logos-map-library/releases/tag/registry-artifact-v0.1.0)
and its SHA-256 file. Verify the archive before extracting it, then check the
bundle's `SHA256SUMS`. `program.bin` is the wallet-compatible container;
`program.elf` is the raw guest for VM tooling. Both represent the same tested
program image. An image ID is not a deployed program account address.

Use the official wallet pinned at LEZ revision
`db66590ab821a4e142c211017a3866d007f6fa77`, configured for the official v0.3
endpoint. The wallet must control a dedicated persistent header account and
six dedicated persistent segment accounts. It also needs a funded payer.
Do not use the deterministic keys in integration fixtures. No secrets or
pre-funded accounts are supplied in this release.

After setting these variables to accounts controlled by that wallet:

```sh
wallet program-loader deploy --elf program.bin \
  --header "$REGISTRY_HEADER" \
  --segments "$SEGMENT_1" "$SEGMENT_2" "$SEGMENT_3" \
             "$SEGMENT_4" "$SEGMENT_5" "$SEGMENT_6" \
  --payer "$FUNDED_ACCOUNT" --immutable
```

This is the upstream deployment command, not a claim that it has been run on
the public zone. The wrapper format, kernel and image have been checked offline;
the raw guest has real VM and isolated-node integration evidence. The wallet
uploads segments tail-to-head and creates the header last. Its pinned deployment
implementation does not automatically resume a partial upload. Preserve account
keys and transaction receipts, inspect resulting state, and do not blindly rerun
with already-written segment accounts.

After deployment, initialize the registry using the reviewed publisher flow,
record the public header address and transaction receipts, then host authentic
regions through the app or [CLI](cli.md). Keep the Storage node available and
run the [coverage verifier](coverage.md). There is no deployed address to enter
in the app yet. Funding, public deployment, persistent coverage and independent
adoption remain incomplete.

The artifact includes original project license texts; dependency notice review
is incomplete. It is an unsigned development prerelease.
