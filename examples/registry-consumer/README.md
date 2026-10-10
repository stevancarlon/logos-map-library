# Standalone registry consumer

A first-party, runnable Basecamp SDK example. It is not independent adoption.
It loads the supported-region catalog and queries a configured v0.3 registry
account by region, with explicit pagination and visible errors. Only the
`prize_maps` core is needed; the distribution app is absent.

Download `prize_maps` from the Map Library catalog using a current `lgpd`, then:

```sh
python3 install-example.py --profile /path/to/new-profile \
  --sdk-lgx /path/to/prize_maps-0.2.0.lgx --lgpm /path/to/lgpm
LOGOS_USER_DIR=/path/to/new-profile /path/to/BasecampExecutable \
  --uri=basecamp://app/prize_maps_consumer
```

Use `lgpm` 0.3.1 or newer and Basecamp 0.3.2 / Qt 6.9.2. The current development
packages are unsigned. A new profile is required; existing data is not replaced.
Enter your sequencer URL and deployed registry **account address**, not the
program image ID. No official-zone registry address is provided yet.

The wrapper in `qml/MapRegistry.js` shows the exact request/response boundary.
Read-only results remain unverified hosting assertions; this example neither
hosts files nor signs transactions. Original code: MIT OR Apache-2.0.
