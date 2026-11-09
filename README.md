# NETTCP.R4P

`NETTCP.R4P` is an independent R4OS protocol module implemented in Zig.

## Package

- Version: `0.1.4`
- Image target: `/R4OS/PROTOCOLS/NETTCP.R4P`
- Image scope: `slim`
- Canonical project manifest: `module.R4MF`

The manifest is the single source of truth for the artifact, imports, image
target, and package metadata.

For RX only, the negotiated `ProtocolBuffer` checksum-valid flag suppresses
the duplicate TCP checksum pass. Every TX and fallback dispatch still uses
the software verifier/builder.

## IPv6 provider

The new ProtocolInit2 path supplies actual bounded IPv6 transport state over
the existing NetIpv6 and NetIcmpv6 owners. It requires the optional complete
PPI2 dispatch, link IO and process-status callbacks. Old IPv4 wire operations
retain their layouts. Scope, ownership, copied records, finite budgets and
feature limits are defined in Contract/API/Ipv6Transport.txt.

## Build

On Windows:

    Build.bat

On Linux or macOS:

    ./Build.sh

The build starters resolve the current local R4OS dependency checkouts through
`Settings.R4S`. The URL and hash entries in `build.zig.zon` record the
last verified standalone dependency identities; workspace builds use the
mapped local checkouts.

## Documentation

Detailed German technical notes from the migration are preserved in
`DOCUMENTATION.de.txt`. Source-transfer provenance is recorded in
`PROVENANCE.txt`.

## License

Original R4OS material is licensed under Apache License 2.0. See `LICENSE`
and `NOTICE`. Any repository-specific external material is documented in
`THIRD_PARTY_NOTICES.md`.
