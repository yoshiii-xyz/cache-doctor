# cache-doctor

cache-doctor explains why an offline Cargo install may fail even when a local
cache contains some artifacts. It performs a bounded, read-only inspection of
the cache and reports evidence about artifacts, index metadata, lockfile
reachability, checksums, source replacement, authentication assumptions, and
stale or malformed entries.

Status: 0.1.0 implementation pending release evidence.

CI: https://github.com/joshiii-xyz/cache-doctor/actions

## Install

```text
cargo install cache-doctor
```

## Quick start

```text
cache-doctor cargo
cache-doctor cargo --offline
cache-doctor inspect ./cache-fixture --format json
cache-doctor inspect ./cache-fixture --format text
```

The `cargo` command uses `CARGO_HOME`, then `HOME/.cargo`, then `.cargo`.
`inspect` accepts a deliberately constructed cache fixture or another local
Cargo home. The scanner does not invoke Cargo and does not make network
requests.

## What it solves

An offline resolver can fail because a lockfile package lacks index metadata,
an artifact is absent, a cached artifact has the wrong checksum, a source is
replaced, credentials are assumed, or an index entry is stale or malformed.
The report makes those observations explicit without attempting a repair.

## How it works

The scanner sorts directory entries, caps filesystem entries and metadata
file reads, parses Cargo.lock package names and versions, finds JSON package
records in registry index files, and hashes `.crate` artifacts up to 64 MiB.
Credential file presence is recorded without reading credential contents.
Reports use a versioned JSON schema and deterministic ordering.

## Commands and library API

The CLI provides `cargo` and `inspect`. The library exposes `inspect_cache`,
`inspect_cargo_home`, `report_json`, and `explain_report`. Use
`cache-doctor --help` for the complete option list.

## Output and exit codes

- Exit code 0 means the requested scan completed without filesystem errors.
- Exit code 1 means the report is incomplete because a scan error occurred.
- Exit code 2 means command-line parsing or report rendering failed.