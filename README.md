# Logos Map Library

Development source for LP-0018: a native Basecamp map distribution app, shared
distribution service, standalone registry SDK and explicit signing publisher.

Each directory (`sdk`, `publisher`, `distribution`, `app`) is a complete pinned
module-builder export with its own README and source hash manifest. Build with
`nix build ./app#lgx-portable`, or select another directory. Repeated shared
sources allow each module to be built independently by the official release
action; these are one project, not independent ecosystem adoption.

Local Linux package loading, registry queries, authenticated publisher access,
checksum handling and isolated Storage workflows have been tested. This is an
incomplete development release, not a prize-completion claim. Public testnet
deployment and coverage, catalog installation, macOS execution, hosted
integration CI and genuine independent adoption remain to be demonstrated.
The collected dependency notices explicitly retain unresolved provenance gaps.

Original code is MIT OR Apache-2.0; see the license files in each module.

A runnable [standalone SDK Explorer example](examples/registry-consumer/README.md)
installs without the distribution app. It is first-party integration evidence.

Terminal users: [complete CLI setup and workflows](docs/cli.md).
