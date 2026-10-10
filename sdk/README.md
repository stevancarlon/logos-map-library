# Map Library for Logos Basecamp

Native C++/Qt/QML and Rust map distribution modules for LP-0018. Development
release: local Linux integration is tested; official-zone deployment, public
coverage, macOS runtime validation and independent adoption remain incomplete.
Packages are unsigned. Dependency notices under `licenses/dependencies` retain
the unresolved upstream texts; this is not a complete license review.

## Build

Install Nix with flakes enabled, then run from this directory:

```sh
nix build .#lgx-portable
```

The selected module is **sdk**.
For an unselected multi-module source export, use `.#sdk-lgx-portable`,
`.#publisher-lgx-portable`, `.#distribution-lgx-portable` or `.#app-lgx-portable`.
The lockfile pins the official module builder, Rust and native dependencies.
Supported build targets are Linux x86_64 and macOS Apple Silicon; declaring a
target is not evidence it was built or run. Basecamp must provide Qt 6.9.2.
The current Linux binaries require glibc 2.38 or newer.

## Modules

| Name | Role | Dependencies |
| --- | --- | --- |
| `prize_maps` | Standalone registry/catalog reads | None |
| `maps_distribution` | Shared catalog, source discovery and registry reads | None |
| `maps_publisher` | Explicit transaction review, encrypted vault and durable outbox | None |
| `logos_maps` | Map Library GUI and file workflows | Both distribution and publisher cores |

The app uses the full shared Rust SDK. Other apps can use `prize_maps` without
installing the distribution app. UI modules are not core dependencies: use
`maps_distribution` when integrating its shared service.

## Read-only service example

Declare `"dependencies": ["prize_maps"]` in your Basecamp module metadata:

```qml
logos.callModuleAsync("prize_maps", "request",
    [JSON.stringify({method: "catalog"})], function(raw) {
        var response = JSON.parse(raw);
        if (typeof response === "string") response = JSON.parse(response);
        if (!response.ok) { console.warn(response.error); return; }
        console.log(response.result.canonical_regions);
    }, 60000);
```

For registry reads, send `method: "query"`, `rpc` (your sequencer URL), `program`
(the deployed v0.3 registry account, not its image ID), `page: 0` and
`filter: {kind: "region", value: "africa/ethiopia"}`. Follow `next_page` until
null, including empty filtered pages. Results are hosting assertions, not proof
of retrievability. No public registry account is supplied in this development
export. The source API is in `source/lez-v03/maps-sdk/src/native.rs`.

## Source and provenance

`source/` contains locked Rust workspaces and their dependencies' local source;
`sdk/`, `distribution/`, `publisher/` and `app/` contain native module sources.
`source-manifest.json` records exported file hashes. This export excludes local
databases, keys, caches and prebuilt native binaries. Original project code is
MIT OR Apache-2.0; third-party notices retain their own licensing.
