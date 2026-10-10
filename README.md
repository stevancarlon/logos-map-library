# Logos Map Library

Development source for LP-0018: a native Basecamp map distribution app, shared
distribution service, standalone registry SDK and explicit signing publisher.

Each directory (`sdk`, `publisher`, `distribution`, `app`) is a complete pinned
module-builder export with its own README and source hash manifest. Build with
`nix build ./app#lgx-portable`, or select another directory. Repeated shared
sources allow each module to be built independently by the official release
action; these are one project, not independent ecosystem adoption.

The preceding releases (app/SDK/distribution 0.2.0 and publisher 0.1.0) have
[successful Linux and Apple Silicon builds](https://github.com/stevancarlon/logos-map-catalog/actions/runs/38024109058)
and [packaged Basecamp runtime checks on both platforms](https://github.com/stevancarlon/logos-map-catalog/actions/runs/38025141148).
The latter use a small synthetic loopback Storage fixture. Separately,
[hosted real-sequencer and authentic Storage integration passed](https://github.com/stevancarlon/logos-map-catalog/actions/runs/38025787623)
on Linux, and a fresh Linux catalog installation was verified.

The current app/SDK/distribution 0.2.1 and publisher 0.1.1 releases have
[passed both platform builds](https://github.com/stevancarlon/logos-map-catalog/actions/runs/38027933050)
and [packaged Linux/Mac runtime checks](https://github.com/stevancarlon/logos-map-catalog/actions/runs/38028353473).
The patch hides a previous success result after a new input error and includes
two recovered upstream license texts. Published archive hashes and both variants
were verified with official `lgx`; fresh Linux catalog installation passed.

This remains an incomplete development release. Official public-testnet
deployment, public hosting coverage, full Mac real-node integration and genuine
independent adoption remain unverified. The collected dependency notices retain
unresolved provenance gaps; no complete license review is claimed.

Installable catalog: [Map Library development catalog](https://raw.githubusercontent.com/stevancarlon/logos-map-catalog/main/logos-repo.json).
Packages are unsigned. No public registry program address is supplied yet.

Original code is MIT OR Apache-2.0; see the license files in each module.

A runnable [standalone SDK Explorer example](examples/registry-consumer/README.md)
installs without the distribution app. It is first-party integration evidence.

Terminal users: [complete CLI setup and workflows](docs/cli.md).

Coverage evaluators: [read-only byte verification and counting](docs/coverage.md).
The verifier has passed an authentic isolated-node fixture; no qualifying public
coverage is claimed.
