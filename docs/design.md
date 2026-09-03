# Design

## Evidence model

The scanner observes local filesystem entries, `.crate` artifact names and
sizes, registry index package records, Cargo.lock package names and versions,
and bounded Cargo configuration text. It associates an artifact with an index
record by the exact `name-version.crate` filename, then compares a bounded
SHA-256 digest with the record's `cksum` field.

## Reachability and diagnosis

Lockfile packages are compared with both index records and observed artifact
names. The report distinguishes missing metadata, missing artifacts, checksum
mismatch, yanked metadata, malformed metadata, stale index timing, source
replacement, and authentication assumptions. Findings describe evidence. A
completed scan is not a claim that Cargo will resolve or build the package.

## Read-only and bounded behavior

The library uses filesystem reads only. It does not invoke Cargo, open a
network connection, log in to a registry, install a package, or read secret
values from credentials files. Directory entries, metadata files, artifact
hashes, findings, and errors have explicit bounds. Reports are sorted before
serialization so equivalent cache fixtures produce deterministic output.

## Configuration handling

The scanner identifies source replacement and registry or source references in
bounded config text. It records only whether a credentials filename is
present. It does not parse or print token values, and it cannot determine
whether a credential is valid.

## Portability boundary

The implementation uses portable Rust filesystem APIs and is release-tested on
Linux. Cargo's on-disk layout can vary by version, registry, source type, and
platform. The scanner reports the structures it recognizes and preserves
errors or omissions rather than claiming universal cache completeness.
