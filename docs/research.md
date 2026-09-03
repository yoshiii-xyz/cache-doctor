# Research notes

Research date: 2026-09-03.

Primary sources:

- Cargo's [`Cargo home`](https://doc.rust-lang.org/cargo/guide/cargo-home.html)
  guide documents the local directory used for registry indexes, cached
  packages, and related state.
- Cargo's [`registry index` reference](https://doc.rust-lang.org/cargo/reference/registry-index.html)
  documents registry index records and checksums used by Cargo.
- Cargo's [`source replacement` reference](https://doc.rust-lang.org/cargo/reference/source-replacement.html)
  documents replacement sources and their configuration model.
- Cargo's [`configuration` reference](https://doc.rust-lang.org/cargo/reference/config.html)
  documents configuration files and the `net.offline` setting.
- Cargo's [`Cargo.toml` versus `Cargo.lock` guide](https://doc.rust-lang.org/cargo/guide/cargo-toml-vs-cargo-lock.html)
  documents the distinct roles of manifest requirements and resolved lockfile
  state.
- Rust's [`read_dir`](https://doc.rust-lang.org/std/fs/fn.read_dir.html)
  documents directory iteration and entry error behavior.
- The [`sha2` crate documentation](https://docs.rs/sha2/latest/sha2/)
  documents the digest implementation used for bounded artifact hashes.

Distribution signal: Cargo package metadata and a standalone CLI repository
are prepared for crates.io. Package availability or download counts are
distribution signals, not evidence of willingness to pay.

Evidence grade: the cited Cargo and Rust documentation supports the concepts
and APIs used by the scanner. The finding taxonomy, output bounds, and
inconclusive interpretations are design inferences selected to keep the tool
read-only and explainable.

Rejected alternatives include a package manager, which would add resolution
and mutation behavior, and a network registry client, which would undermine
the offline evidence boundary. Decision: keep the release to local Cargo
cache inspection, bounded hashing, deterministic reports, and explicit limits.
