# Limits and non-goals

The 0.1.0 MVP has these limits:

- Cargo is the only ecosystem covered by release evidence.
- The scanner inspects local paths. It does not fetch, resolve, install,
  repair, delete, or modify packages.
- It never invokes Cargo or uses the network. It cannot prove that an offline
  build will succeed.
- Directory traversal is capped at 512 filesystem entries. Bounded metadata
  files are capped at 1 MiB, artifact hashing at 64 MiB, and JSON output at
  1 MiB.
- Artifact matching relies on an exact `name-version.crate` filename and
  recognized index JSON records. Alternate or future cache encodings may be
  reported as absent or malformed.
- Source replacement and authentication results are assumptions from bounded
  configuration and filename presence. Credential validity is not tested and
  credential values are not read.
- Stale index comparison uses filesystem modification times and can be
  affected by timestamp resolution or clock behavior.
- Concurrent cache changes can make a report incomplete or internally mixed.

The tool is not a package manager, dependency resolver, registry client,
cache repair tool, secret scanner, or build oracle.
