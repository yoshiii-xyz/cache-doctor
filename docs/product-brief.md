# Product brief

cache-doctor explains why an offline Cargo install cannot resolve or fetch a
package even when some artifacts appear cached.

Target users are Rust maintainers, release engineers, and build operators who
need a bounded local evidence report before deciding whether a cache is
complete, stale, mismatched, or configured for a source that is not available.

The first commands are:

```text
cache-doctor cargo
cache-doctor cargo --offline
cache-doctor inspect cache-path --format json
```

The switching wedge is a read-only report that connects lockfile reachability,
index metadata, artifact presence, checksums, source replacement, and
authentication assumptions without becoming a package manager or attempting a
repair.

Evidence and inference are separate. Cargo documentation linked in
[`docs/research.md`](research.md) supports the documented cache, lockfile,
source replacement, and offline concepts. The diagnosis categories and the
switching wedge are design choices for this focused MVP, not market-size or
adoption claims.

Non-goals are package resolution, downloads, installation, repair, registry
login, secret inspection, a GUI, and a hosted service.
